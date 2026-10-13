# Definition of Done — poweramp-license

## 1. PLAN.md with failure conditions first

Present. Among the conditions is that **the comparison offset must be pinned by
measurement**, and that **a test which moves with the constant it tests proves
nothing**. Both turned out to matter: the offset was 1, not the 5 the
decompiler shows, and a test was tautological until rewritten.

## 2. RESEARCH / notes

`../poweramp-re/NOTES.md` records the reversing: the entitlement state machine and
every constant (`l111`, `llll`, `l1ll`, `l1l1`, `f892`, `f8930x1`, `f889enum`),
the broadcast that delivers the result, the unlocker's role and its
`ILicenseResultListener` import, the anti-tamper certificate check, and the loud
`smam()` response. The constant `L` is quoted from the class file.

## 3. Working code

`internal/poweramp` (rules + certificate check), `cmd/poweramp-license` (CLI),
444 lines non-test, zero dependencies.

```
BUILD=0   VET=0   gofmt clean
```

## 4. Tests actually executed

```
$ go test ./...
ok  github.com/yondaime-kun/poweramp-license/internal/poweramp
TEST=0
$ go test -race ./...
RACE=0
```

**24 tests, 0 failures.** Measured: 444 lines non-test, 262 lines test.

**Mutation testing: 10/10 caught** — threshold 229→1 and 229→228, `==`→`>=` on the
verified check, offset moved to 0, 2 and 5, length guard removed, empty-trusted
guard removed, debuggable bit changed, `Trial` unhooked from `Full`.

**Two real test bugs were found and fixed, not worked around:**

1. A short-certificate test used a repeated byte as the trusted value, so a
   truncated certificate matched by accident. The value is now a rising sequence
   that cannot match a truncated block.
2. The offset test's data helper read `CertOffset`, so changing the constant moved
   the data with it and the mutation **passed**. The helper now uses an
   independently recorded literal, and the mutation is caught.

**Corroboration against real artifacts:**

```
poweramp.apk  (com.maxmpz.audioplayer 813, md5 403a8ef4584f8ef80bf23e83d2875d44)
              certificate matches the DEX constant L, 96/96 bytes from offset 1
unlock.apk    (com.maxmpz.audioplayer.unlock 302, md5 73d7a66def6a750a8a7e6d7a8e552a8d)
              same signer, as an unlocker package must be
a repack with a different key
              does not match; the app would flag changed_signature
```

The extracted certificate's subject (`CN=Maxim Petrov, O=Maxim Petrov,
L=Mytischi, ST=Moscow Reg., C=RU`, serial `4cac33b5`) is the text visible inside
`L`, which is what makes the recovery checkable rather than asserted.

## 5. Honest README

`README.md` states what the tool is and is not, gives the threshold rule and the
measured offset with the byte-by-byte evidence, and carries a Limitations section
that says plainly it is not a bypass, that the certificate scan is a heuristic
rather than a PKCS#7 parse, and that `CertOffset` is measured on one version.

## 6. Commit

See repository history.
