# Poweramp entitlement rules — plan

## What was to be built

A reimplementation of how Poweramp (`com.maxmpz.audioplayer`) decides between
trial and full version, from the app and its unlocker rather than from any
description of them.

The target was chosen before reading it, on stated criteria: a **paid** app
(Poweramp is a paid audio player with a paid unlocker), **well known**, **not
previously reversed** here, and **still without a public bypass**. The
acquisition path had to exist too: the APKs are mirrored, and their MD5s were
checked against the mirror's own metadata before use.

## Failure conditions, written before the code

- If the entitlement rule cannot be read as a definite rule — thresholds,
  values, the lot — then any reimplementation would be a guess. Stop.
- If the certificate the app compares cannot be recovered from the app itself,
  then the check cannot be reproduced and the tool must not claim to.
- **If the offset the comparison starts at cannot be established by measurement**,
  the check is guesswork even if it appears to work on one sample. The offset had
  to be pinned against real data, not taken from the decompiled initialiser.
- If a test can be satisfied by a change to the constant it tests, it proves
  nothing; any such test must be rewritten before the suite is trusted.
- If the certificate comparison cannot be shown to both match and not match on
  real APKs, no verification has been demonstrated.

## Scope

In scope: the entitlement threshold rule, the certificate comparison, the
debuggable-build rule.

Out of scope, and not to be implied: producing a license result Poweramp would
accept. That is issued through Google Play to the unlocker, and this work makes
no claim about it.
