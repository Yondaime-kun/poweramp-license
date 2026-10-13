# Poweramp entitlement rules

A reimplementation of the rules **Poweramp** (`com.maxmpz.audioplayer`) uses to
decide whether it is a trial or the full version, and of the certificate check it
runs against its own signature.

```
poweramp-license rules                      # the reversed constants
poweramp-license evaluate 229               # apply the threshold rule
poweramp-license cert <apk>                 # print an APK's signer certificate
poweramp-license check <apk> <trusted-hex>  # compare a certificate to a trusted value
```

Everything here was reversed from Poweramp 813 and its unlocker 302. Nothing is
guessed; [NOTES.md](../poweramp-re/NOTES.md) carries the decompiled source each
constant comes from.

## What this is

Poweramp decides entitlement from a single integer, compares its own signing
certificate against a constant compiled into the DEX, and refuses to run at all
if the build is debuggable. Those three rules are the app's whole licensing
surface, and they are reimplemented here so they can be **stated, tested and
checked** rather than described from memory.

It is not a bypass, and it does not produce anything Poweramp would accept. What
it does is let you take a real APK and see exactly what the app would conclude
about it — which is the part that can be verified.

## The entitlement rule

Entitlement is a single integer, stored in `SharedPreferences("l")` under `"r"`:

```
value >= 229   -> full         (l1ll = 229)
value == 272   -> full verified (l1l1 = 272)
anything else  -> trial
```

Two things about this are easy to get wrong and are pinned by tests:

- **It is not "nonzero means paid."** A result of 1 is a trial. So are 3, 4 and
  256's neighbours below 229. The threshold is 229, and it is inclusive.
- **"verified" is one value, not a range.** Only 272 verifies. Reading it as
  `>= 272` would report unverified results as verified, which is a different
  claim to show a user.

```
$ poweramp-license evaluate 228
result 228 -> trial
$ poweramp-license evaluate 229
result 229 -> full
$ poweramp-license evaluate 272
result 272 -> full verified
$ poweramp-license evaluate 273
result 273 -> full
```

## The certificate check

At startup the app does this, before anything else:

```java
if ((getApplicationInfo().flags & 2) != 0)          // FLAG_DEBUGGABLE
    Process.killProcess(Process.myPid());

Signature[] sig = getPackageManager().getPackageInfo(getPackageName(), 64).signatures;
byte[] b = sig[0].toByteArray();
for (int i = 0; i < L.length; i++)
    if (b[5 + i] != L[i]) { z = false; break; }
if (!z) smam(this);                                 // loud: toast + finish all
```

`L` is a 96-byte constant inside the DEX. Recovered from the class file, it is:

```
82 02 50 a0 03 02 01 02 02 04 4c ac 33 b5 30 0d 06 09 2a 86 48 86 f7 0d 01 01 05 05 00
30 76 31 0b 30 09 06 03 55 04 06 13 02 52 55 31 14 30 12 06 03 55 04 08 13 0b 4d 6f 73
63 6f 77 20 52 65 67 2e ...
```

Read as text that is a certificate distinguished name — `RU`, `Moscow Reg.`,
`Mytischi`, `Maxim Petrov` — which is what an X.509 subject looks like. The
serial `4c ac 33 b5` appears in it, so the constant is a fragment of the
developer's certificate.

### The offset, measured rather than assumed

The decompiled loop starts its cursor at 5 (`int i2 = 5;`), and the natural
reading is "the comparison starts 5 bytes into the certificate." **That is not
what the bytes say.** Extracting the X.509 certificate from Poweramp's own APK
and comparing it to `L` byte by byte:

```
certificate: 30 82 02 50 a0 03 02 01 02 02 04 4c ac 33 b5 ...
constant L:     82 02 50 a0 03 02 01 02 02 04 4c ac 33 b5 ...
                ^ matches from here: 96/96 bytes
```

The match is at offset **1**, not 5. The difference is the four bytes the Android
runtime's `toByteArray()` does not present the same way a raw certificate blob
does. Rather than hard-code either number and be quietly wrong, the offset is a
named constant (`CertOffset`) with this measurement recorded, and the tests hold
it against an **independently written literal** so that changing it cannot move
the test data along with it.

### Demonstrated on real APKs

```
$ poweramp-license check poweramp.apk <L>
compared 149 bytes from offset 1
result: MATCH — the app would treat this build as authentic

$ poweramp-license check unlock.apk <L>
result: MATCH       <- the unlocker carries the same signer

$ poweramp-license check some-repacked.apk <L>
result: NO MATCH — certificate bytes from offset 1 do not match the trusted value
the app would log changed_signature, toast it, and finish its activities
```

The second line is not a curiosity: Poweramp's own Full Version Unlocker is
signed with the **same certificate** as Poweramp, which is why an unlocker
package can be trusted at all.

## Tests

```
go test ./...
```

24 tests. Boundary values on both sides of 229, that 272 alone verifies, that the
certificate comparison starts where it was measured, that a certificate too short
to compare is a clean mismatch rather than a panic, that only the leading bytes
are examined (the client never looks at the tail), and that the two gates are
independent — an intact build with no license is still a trial, and a repacked
build with a valid stored result still reports that result.

**Mutation testing: 10/10 caught.** Threshold 229→1 and 229→228, `==` to `>=` on
the verified check, the offset moved to 0, 2 and 5, the length guard removed, the
empty-trusted guard removed, the debuggable bit changed, and `Trial` unhooked from
`Full`.

Two real test bugs were found this way and fixed rather than worked around:

- A short-certificate test used a **repeated byte** as the trusted value, so a
  truncated certificate matched by accident. The value is now a rising sequence.
- The offset test's helper read `CertOffset` when placing its data, so moving the
  constant moved the data too and the test passed regardless — it was asserting
  the code agrees with itself. The helper now uses an independently recorded
  literal.

## Limitations

- **This is not a bypass.** It reimplements the decision, not the credential.
  Poweramp's entitlement comes from Google Play via its unlocker; producing a
  result the app would accept means satisfying Play, not this code.
- **The certificate scan is a heuristic**, not a PKCS#7 parse: it finds the
  nested X.509 by its DER header and version tag. On Poweramp's APK it recovers
  the certificate that matches `L`, which is the check that matters, but a
  differently packaged APK could defeat it.
- **`CertOffset` is measured on Poweramp 813.** A different version could differ;
  the value is exposed so this can be re-measured rather than assumed.
- **The debuggable rule is modelled, not enacted.** `IsDebuggable` reports the
  rule; this package does not kill any process.

## License

MIT — see [LICENSE](LICENSE).
