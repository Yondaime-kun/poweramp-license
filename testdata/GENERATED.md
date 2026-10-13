# testdata

No APK is checked in here. Poweramp is a paid application and redistributing its
binary is not something this repository does.

## What the tests use instead

The tests construct certificate-like blobs in memory and exercise the rules
directly, so the suite runs with no external artifacts:

- `cert(tail)` places a value at the measured offset so the comparison can be
  driven from both directions.
- The threshold tests enumerate values on both sides of 229 and around 272.

## What the real artifacts established

Separately from the tests, the implementation was checked against the actual
APKs by the CLI:

- Poweramp 813's own certificate matches the compiled-in constant `L` from offset
  1 (96 of 96 bytes), where `L` is the 96-byte array read out of
  `Application.java`.
- The Full Version Unlocker carries the same signer.
- An APK signed with a different key does not match.

Those checks are reproducible with `poweramp-license check <apk> <L-hex>` if you
obtain the APKs yourself; the constant `L` is quoted in README.md and NOTES.md.
