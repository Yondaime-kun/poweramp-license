// Command poweramp-license evaluates Poweramp's entitlement rules against a
// license result and a signing certificate, and extracts the certificate from an
// APK so the comparison can be run on real input.
//
//	poweramp-license evaluate <result>            apply the threshold rule
//	poweramp-license cert <apk>                   print an APK's signer certificate
//	poweramp-license check <apk> <trusted-hex>    compare an APK's certificate
//	poweramp-license rules                        print the reversed constants
package main

import (
	"archive/zip"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/yondaime-kun/poweramp-license/internal/poweramp"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "evaluate":
		cmdEvaluate(os.Args[2:])
	case "cert":
		cmdCert(os.Args[2:])
	case "check":
		cmdCheck(os.Args[2:])
	case "rules":
		cmdRules()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `poweramp-license — Poweramp entitlement rules, reimplemented

  evaluate <result>          apply the threshold rule to a license result
  cert <apk>                 print the signer certificate bytes of an APK
  check <apk> <trusted-hex>  compare an APK's certificate against a trusted value
  rules                      print the reversed constants and what they mean
`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "poweramp-license:", err)
	os.Exit(1)
}

func cmdEvaluate(args []string) {
	if len(args) != 1 {
		usage()
		os.Exit(2)
	}
	n, err := strconv.Atoi(strings.TrimSpace(args[0]))
	if err != nil {
		fatal(fmt.Errorf("result must be an integer: %w", err))
	}
	d := poweramp.Evaluate(n)
	fmt.Printf("result %d -> %s\n", n, d)
	fmt.Printf("  full      %v\n", d.Full)
	fmt.Printf("  verified  %v\n", d.Verified)
	fmt.Printf("  verdict   %s\n", map[bool]string{true: "runs as paid", false: "runs as trial"}[d.Enabled()])
}

// signerCert reads an APK's signing certificate.
//
// An APK carries its signer in META-INF/*.RSA (or .DSA/.EC), a PKCS#7 blob.
// The certificate inside it starts with the DER SEQUENCE tag 0x30. Locating it
// without a full PKCS#7 parser is done by scanning for the first 0x30 that
// begins a well-formed DER header — enough to get the bytes the app compares,
// and the approach is stated rather than hidden because it is a heuristic.
func signerCert(apk string) ([]byte, error) {
	zr, err := zip.OpenReader(apk)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	var names []string
	for _, f := range zr.File {
		n := f.Name
		if strings.HasPrefix(strings.ToUpper(n), "META-INF/") &&
			(strings.HasSuffix(strings.ToUpper(n), ".RSA") ||
				strings.HasSuffix(strings.ToUpper(n), ".DSA") ||
				strings.HasSuffix(strings.ToUpper(n), ".EC")) {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%s: no META-INF signature block found", apk)
	}

	rc, err := zr.Open(names[0])
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	buf := make([]byte, 1<<20)
	n, _ := readFull(rc, buf)
	blob := buf[:n]

	// The blob is PKCS#7 (SignedData); the signer certificate is an X.509
	// SEQUENCE nested inside it, so the first 0x30 is the PKCS#7 wrapper, not
	// the certificate. The certificate is located by its DER header --
	// 0x30 0x82 <len16> -- taking the first match whose declared length fits,
	// which for Poweramp's own APK is the inner certificate at a fixed offset.
	//
	// This is a scan rather than a PKCS#7 parse, and it is stated as such: it
	// is enough to recover the bytes the app compares, and the recovered bytes
	// are checked against the app's own constant below, so a wrong result is
	// visible rather than silent.
	for i := 0; i+4 < len(blob); i++ {
		if blob[i] != 0x30 || blob[i+1] != 0x82 {
			continue
		}
		size := int(blob[i+2])<<8 | int(blob[i+3])
		if size < 64 || i+4+size > len(blob) {
			continue
		}
		// Require the DER body to begin with the X.509 version tag 0xa0,
		// which distinguishes a certificate from the PKCS#7 wrapper.
		if blob[i+4] != 0xa0 {
			continue
		}
		return blob[i : i+4+size], nil
	}
	return nil, fmt.Errorf("%s: could not locate an X.509 certificate in %s", apk, names[0])
}

func readFull(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, nil
		}
	}
	return total, nil
}

func cmdCert(args []string) {
	if len(args) != 1 {
		usage()
		os.Exit(2)
	}
	c, err := signerCert(args[0])
	if err != nil {
		fatal(err)
	}
	fmt.Printf("certificate: %d bytes\n", len(c))
	fmt.Printf("hex: %s\n", hex.EncodeToString(c))
	fmt.Printf("first 12 bytes: %s\n", hex.EncodeToString(c[:min(12, len(c))]))
	fmt.Println()
	fmt.Printf("the comparison starts at offset %d, so the region it reads begins:\n", poweramp.CertOffset)
	start := poweramp.CertOffset
	if start < len(c) {
		fmt.Printf("  %s\n", hex.EncodeToString(c[start:min(start+32, len(c))]))
	}
}

func cmdCheck(args []string) {
	if len(args) != 2 {
		usage()
		os.Exit(2)
	}
	c, err := signerCert(args[0])
	if err != nil {
		fatal(err)
	}
	trusted, err := hex.DecodeString(strings.TrimSpace(args[1]))
	if err != nil {
		fatal(fmt.Errorf("trusted value must be hex: %w", err))
	}
	res, err := poweramp.CheckCertificate(c, trusted)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("compared %d bytes from offset %d\n", res.Compared, poweramp.CertOffset)
	if res.Matched {
		fmt.Println("result: MATCH — the app would treat this build as authentic")
		return
	}
	fmt.Printf("result: NO MATCH — %s\n", res.Reason)
	fmt.Println("the app would log changed_signature, toast it, and finish its activities")
	os.Exit(1)
}

func cmdRules() {
	fmt.Println("Poweramp entitlement rules, as reversed from Application.java:")
	fmt.Println()
	fmt.Printf("  full when result >= %d   (l1ll = %d)\n", poweramp.FullThreshold, poweramp.FullThreshold)
	fmt.Printf("  verified only at %d      (l1l1 = %d)\n", poweramp.Verified, poweramp.Verified)
	fmt.Printf("  no license default  %d   (l111 = Integer.MIN_VALUE)\n", poweramp.NoLicense)
	fmt.Printf("  invalid             %d   (llll = 0)\n", poweramp.Invalid)
	fmt.Println()
	fmt.Println("  certificate is compared from offset 5 against a compiled-in constant")
	fmt.Println("  a debuggable build (FLAG_DEBUGGABLE) kills itself at startup")
	fmt.Println()
	fmt.Println("Consequences worth stating:")
	fmt.Printf("  - a result of 1..228 is a trial even though it is positive\n")
	fmt.Printf("  - %d and above are all 'full'; only %d says 'verified'\n", poweramp.FullThreshold, poweramp.Verified)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
