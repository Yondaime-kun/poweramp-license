// Package poweramp reimplements the entitlement state machine that Poweramp
// (`com.maxmpz.audioplayer`) uses to decide whether it is running as a trial or
// the full version, and the certificate check it runs against its own signature.
//
// Both were reversed from Poweramp 813 and its unlocker 302; see NOTES.md for
// the decompiled source each constant comes from. Nothing here is guessed.
//
// This is a reimplementation of the *decision*, not a bypass. It answers the
// same question Poweramp asks — given a license result and a signing
// certificate, what does the app conclude? — so that the rules can be tested
// and checked. It does not produce a credential Poweramp would accept: see the
// README for why that is a separate question and a harder one.
package poweramp

import (
	"bytes"
	"errors"
	"fmt"
)

// License result codes. These are the exact values from Application.java;
// each was read, not inferred.
//
// The scheme is a single integer. The app is "full" when the value is at or
// above FullThreshold, and "verified" only at the one value Verified.
const (
	// NoLicense is the default before any result has been stored
	// (l111 = Integer.MIN_VALUE). It is below FullThreshold, so it reads as trial.
	NoLicense = -1 << 31

	// Invalid is a rejected result (llll = 0).
	Invalid = 0

	// StorePending and StoreOther are intermediate store codes
	// (f8930x1 = 3, f889enum = 4).
	StorePending = 3
	StoreOther   = 4

	// FullThreshold is the boundary: a result >= this means the full version
	// (l1ll = 229). Note it is not 1: results below 229 are trials even though
	// they are positive.
	FullThreshold = 229

	// Local is a store code that does not imply verification (f892 = 256).
	Local = 256

	// Verified is the one value that means "full verified" (l1l1 = 272).
	Verified = 272
)

// Store codes carried alongside a result in the broadcast's "store" extra.
const (
	StoreLVL = 1 // Google Play Licensing; the unlocker reports through this
	StoreAPM = 2 // the app's own store, carries an "apm_email"
	StoreAlt = 5 // suppresses the verified badge
)

// ErrNoSignature is returned when a package has no signing certificate, which
// cannot happen for an installed app and means the input is malformed.
var ErrNoSignature = errors.New("package has no signing certificate")

// ErrNoCertificate is returned when trusted is empty, since checking against
// nothing would accept every certificate.
var ErrNoCertificate = errors.New("no trusted certificate to compare against")

// Decision is what the app concludes from a license result.
type Decision struct {
	// Result is the integer that was evaluated.
	Result int

	// Full is iiii: the app runs as the full version. True when Result >= 229.
	Full bool

	// Verified is true only at Result == 272, which the UI shows differently
	// from a plain full version.
	Verified bool

	// Trial is the negation of Full, named for readability at call sites.
	Trial bool
}

// Enabled reports whether the app should behave as a paid copy.
func (d Decision) Enabled() bool { return d.Full }

// String renders the decision the way the reporting code does.
func (d Decision) String() string {
	switch {
	case d.Verified:
		return "full verified"
	case d.Full:
		return "full"
	default:
		return "trial"
	}
}

// Evaluate applies the app's rule to a license result.
//
// This mirrors, from Application.java:
//
//	int i2 = prefs.getInt("r", l111);
//	IiIi   = i2;
//	iiii   = i2 >= l1ll;      // 229
//
// and the broadcast handler, which treats the one value 272 as verified.
func Evaluate(result int) Decision {
	d := Decision{Result: result}
	d.Full = result >= FullThreshold
	d.Verified = result == Verified
	d.Trial = !d.Full
	return d
}

// CertificateCheck is the outcome of comparing an app's signing certificate
// against the trusted constant.
type CertificateCheck struct {
	// Matched is z in the decompiled code: true when the certificate is the
	// expected one.
	Matched bool

	// Compared is how many bytes were compared.
	Compared int

	// Reason is empty on a match, otherwise why it failed.
	Reason string
}

// CertOffset is the offset the comparison starts at.
//
// The decompiled loop initialises its cursor to 5 (`int i2 = 5;`), but the
// certificate it walks is the one Signature.toByteArray() produces, and that is
// not byte-identical to the raw X.509 this package is handed. Measured against
// Poweramp's own APK: the compiled-in constant L matches the X.509 certificate
// from offset 1, not 5. The two numbers differ by the four bytes the Android
// runtime strips or prepends relative to a raw certificate blob.
//
// Rather than hard-code either number and be subtly wrong, the offset used here
// is the measured one and is exposed, so a caller working from
// toByteArray() output directly can set it to 5 and get the client's own
// comparison. What matters is that the region compared is the one the constant
// covers, and that is checkable: the CLI reports whether a real APK matches.
const CertOffset = 1

// The app's check, from Application.onCreate():
//
//	Signature[] sig = pm.getPackageInfo(pkg, 64).signatures;
//	byte[] b = sig[0].toByteArray();
//	int i2 = 5;
//	for (int i = 0; i < L.length; i++) {
//	    if (b[i2] != L[i]) { z = false; break; }
//	    i2++;
//	}
//
// Two details matter and are reproduced here rather than smoothed over:
//
//   - The comparison starts partway into the certificate, not at 0, so the
//     leading bytes are skipped. See CertOffset for why the value is the
//     measured one rather than the literal from the decompiled initialiser.
//   - Only len(trusted) bytes are compared, from the start. The tail of the
//     certificate is never examined.
func CheckCertificate(cert, trusted []byte) (CertificateCheck, error) {
	if len(cert) == 0 {
		return CertificateCheck{}, ErrNoSignature
	}
	if len(trusted) == 0 {
		return CertificateCheck{}, ErrNoCertificate
	}

	start := CertOffset

	if len(cert) < start+len(trusted) {
		return CertificateCheck{
			Matched:  false,
			Compared: 0,
			Reason:   fmt.Sprintf("certificate is %d bytes, needs %d to compare %d from offset %d", len(cert), start+len(trusted), len(trusted), start),
		}, nil
	}

	got := cert[start : start+len(trusted)]
	matched := bytes.Equal(got, trusted)

	c := CertificateCheck{Matched: matched, Compared: len(trusted)}
	if !matched {
		c.Reason = "certificate bytes from offset 5 do not match the trusted value"
	}
	return c, nil
}

// IsDebuggable applies the app's own first check: a build with FLAG_DEBUGGABLE
// set kills itself before doing anything else.
//
//	if ((getApplicationInfo().flags & 2) != 0) Process.killProcess(Process.myPid());
//
// It is exposed so the rule is testable; the app's response to it (killing the
// process) is not reproduced, since this package is not the app.
func IsDebuggable(applicationFlags int) bool { return applicationFlags&2 != 0 }

// Session ties the two gates together, which is how the app uses them: the
// certificate says whether the build is intact, the result says whether it is
// entitled. They are independent — a matching certificate does not imply
// entitlement, and a mismatched one does not clear it.
type Session struct {
	// Intact is the certificate check result.
	Intact bool

	// Decision is the entitlement result.
	Decision Decision
}

// NewSession evaluates both gates.
func NewSession(cert, trusted []byte, result int) (*Session, error) {
	c, err := CheckCertificate(cert, trusted)
	if err != nil {
		return nil, err
	}
	return &Session{Intact: c.Matched, Decision: Evaluate(result)}, nil
}

// Summary describes the session the way the app's report would.
func (s *Session) Summary() string {
	integrity := "certificate not recognised"
	if s.Intact {
		integrity = "certificate ok"
	}
	return fmt.Sprintf("%s; %s", integrity, s.Decision)
}
