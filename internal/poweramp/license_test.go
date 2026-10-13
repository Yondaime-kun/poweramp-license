package poweramp

import (
	"bytes"
	"testing"
)

// cert wraps arbitrary bytes the way a Signature.toByteArray() would, so the
// offset-5 behaviour can be exercised directly.
// cert builds a certificate-like blob that carries want at the absolute
// position measured from Poweramp's own APK.
//
// The position is written as a literal on purpose. If this helper used
// CertOffset, then changing CertOffset would move the test data with it and the
// offset test would still pass -- it would be asserting that the code agrees
// with itself. The literal is the value measured independently from the APK's
// certificate against the constant compiled into the DEX.
const measuredOffset = 1

func cert(tail []byte) []byte {
	head := bytes.Repeat([]byte{0x00}, measuredOffset)
	return append(head, tail...)
}

func TestEvaluateThreshold(t *testing.T) {
	// 229 is the boundary. Both sides of it are pinned, and so is the value the
	// constant would be if someone "fixed" it to 1 — a positive result below 229
	// is a trial, which is the part that is easy to get wrong.
	cases := []struct {
		result int
		full   bool
		name   string
	}{
		{NoLicense, false, "no license"},
		{Invalid, false, "invalid"},
		{StorePending, false, "store pending (3)"},
		{StoreOther, false, "store other (4)"},
		{1, false, "1 is still a trial, not full"},
		{100, false, "100 below the threshold"},
		{228, false, "one below the threshold"},
		{229, true, "exactly the threshold"},
		{230, true, "one above the threshold"},
		{Local, true, "256 is above, so full"},
		{Verified, true, "272 is full as well as verified"},
		{1000, true, "far above"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Evaluate(c.result)
			if d.Full != c.full {
				t.Errorf("Evaluate(%d).Full = %v, want %v", c.result, d.Full, c.full)
			}
			if d.Trial == d.Full {
				t.Errorf("Evaluate(%d): Trial (%v) must be the negation of Full (%v)", c.result, d.Trial, d.Full)
			}
		})
	}
}

func TestEvaluateVerifiedIsOnlyOneValue(t *testing.T) {
	// "full verified" is a single value, not a range. If this were written as
	// >= 272 it would report unverified results as verified, which is a
	// different claim to the user.
	if d := Evaluate(Verified); !d.Verified {
		t.Error("272 must be verified")
	}
	for _, r := range []int{271, 273, 300, FullThreshold, NoLicense} {
		if d := Evaluate(r); d.Verified {
			t.Errorf("Evaluate(%d).Verified = true, want false (only 272 verifies)", r)
		}
	}
}

func TestDecisionString(t *testing.T) {
	if got := Evaluate(NoLicense).String(); got != "trial" {
		t.Errorf("no license renders %q, want trial", got)
	}
	if got := Evaluate(229).String(); got != "full" {
		t.Errorf("229 renders %q, want full", got)
	}
	if got := Evaluate(272).String(); got != "full verified" {
		t.Errorf("272 renders %q, want full verified", got)
	}
}

func TestCertificateMatchesAtCertOffset(t *testing.T) {
	trusted := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	c := cert(trusted)

	// The same bytes at offset 0 must NOT match, because the comparison does
	// not start at 0.
	var wrong []byte
	wrong = append(wrong, trusted...)
	wrong = append(wrong, bytes.Repeat([]byte{0x00}, CertOffset)...)

	ok, err := CheckCertificate(c, trusted)
	if err != nil {
		t.Fatalf("CheckCertificate: %v", err)
	}
	if !ok.Matched {
		t.Errorf("certificate should match: %s", ok.Reason)
	}
	if ok.Compared != len(trusted) {
		t.Errorf("compared %d bytes, want %d", ok.Compared, len(trusted))
	}

	bad, err := CheckCertificate(wrong, trusted)
	if err != nil {
		t.Fatalf("CheckCertificate: %v", err)
	}
	if bad.Matched {
		t.Error("a certificate whose offset-0 bytes match must not match, since the comparison is not from 0")
	}
}

// TestCertificateOffsetIsNotZero pins the offset itself. If the start were
// 0 the certificates below would swap outcomes, so this fails loudly rather
// than silently comparing the wrong region.
func TestCertificateOffsetIsNotZero(t *testing.T) {
	trusted := []byte{0x01, 0x02, 0x03}

	// Certificate whose first three bytes are the trusted value: matches only
	// if the comparison starts at 0.
	atZero := append([]byte{}, trusted...)
	atZero = append(atZero, bytes.Repeat([]byte{0x00}, CertOffset+2)...)

	res, err := CheckCertificate(atZero, trusted)
	if err != nil {
		t.Fatalf("CheckCertificate: %v", err)
	}
	if res.Matched {
		t.Error("comparison appears to start at offset 0, which is not where the client compares")
	}
}

func TestCertificateShortIsRejectedNotPanicked(t *testing.T) {
	// A certificate shorter than 5 + len(trusted) cannot be compared. It must
	// be a clean mismatch, not a slice out of range.
	// Use a pattern that cannot match by accident when truncated: the trusted
	// value is a rising sequence, so a short certificate filled with a constant
	// cannot equal it. (An earlier version of this test used a repeated byte and
	// passed a too-short certificate, which is why the value is not constant.)
	trusted := make([]byte, 32)
	for i := range trusted {
		trusted[i] = byte(i + 1)
	}
	for _, n := range []int{0, 1, CertOffset, CertOffset + 1, 10, 36} {
		c := make([]byte, n)
		for i := range c {
			c[i] = byte(i + 1)
		}
		res, err := CheckCertificate(c, trusted)
		if err != nil {
			// zero length is a distinct error, which is fine
			if n == 0 {
				continue
			}
			t.Fatalf("len %d: unexpected error %v", n, err)
		}
		if res.Matched {
			t.Errorf("len %d: matched, but the certificate is too short to hold %d+%d bytes", n, CertOffset, len(trusted))
		}
		if res.Reason == "" {
			t.Errorf("len %d: mismatch must carry a reason", n)
		}
	}
}

func TestCertificateOnlyLeadingBytesCompared(t *testing.T) {
	// The app compares exactly len(trusted) bytes and never looks at the tail.
	// A certificate that agrees on the compared region but differs afterwards
	// must still match — that is the client's actual behaviour, and a stricter
	// reimplementation would disagree with it.
	trusted := []byte{0x0A, 0x0B}
	c := cert(trusted)
	c = append(c, 0xFF, 0xEE, 0xDD) // different tail, never examined

	res, err := CheckCertificate(c, trusted)
	if err != nil {
		t.Fatalf("CheckCertificate: %v", err)
	}
	if !res.Matched {
		t.Error("tail bytes are not compared by the client, so this must match")
	}
}

func TestEmptyTrustedRejected(t *testing.T) {
	// Comparing against nothing would accept everything, so it is an error
	// rather than a match.
	if _, err := CheckCertificate(cert([]byte{1, 2}), nil); err != ErrNoCertificate {
		t.Fatalf("err = %v, want ErrNoCertificate", err)
	}
}

func TestEmptyCertificateRejected(t *testing.T) {
	if _, err := CheckCertificate(nil, []byte{1, 2}); err != ErrNoSignature {
		t.Fatalf("err = %v, want ErrNoSignature", err)
	}
}

func TestIsDebuggable(t *testing.T) {
	if IsDebuggable(0) {
		t.Error("flags 0 is not debuggable")
	}
	if !IsDebuggable(2) {
		t.Error("flag bit 1 (FLAG_DEBUGGABLE) must report debuggable")
	}
	if !IsDebuggable(0x2 | 0x1000) {
		t.Error("the debuggable bit must be read regardless of other flags")
	}
	if IsDebuggable(0x1000) {
		t.Error("an unrelated flag must not report debuggable")
	}
}

func TestSessionGatesAreIndependent(t *testing.T) {
	trusted := []byte{0xDE, 0xAD}
	good := cert(trusted)
	bad := cert([]byte{0x00, 0x00})

	// Intact build, no entitlement: still a trial. The certificate says the
	// build is authentic, not that it was paid for.
	s1, err := NewSession(good, trusted, NoLicense)
	if err != nil {
		t.Fatal(err)
	}
	if !s1.Intact || s1.Decision.Full {
		t.Errorf("intact + no license: intact=%v full=%v, want true/false", s1.Intact, s1.Decision.Full)
	}

	// Entitled result but a repacked certificate: the app would flag the build
	// yet the stored entitlement is unchanged. These are separate gates and the
	// model must not conflate them.
	s2, err := NewSession(bad, trusted, Verified)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Intact {
		t.Error("a foreign certificate must not be reported as intact")
	}
	if !s2.Decision.Verified {
		t.Error("the entitlement gate must still report the result it was given")
	}
}

func TestSessionSummary(t *testing.T) {
	trusted := []byte{0x01}
	s, err := NewSession(cert(trusted), trusted, Verified)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Summary(); got != "certificate ok; full verified" {
		t.Errorf("Summary = %q", got)
	}
	s2, err := NewSession(cert([]byte{0x02}), trusted, NoLicense)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.Summary(); got != "certificate not recognised; trial" {
		t.Errorf("Summary = %q", got)
	}
}
