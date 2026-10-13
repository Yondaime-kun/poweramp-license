#!/bin/sh
# Build poweramp-license, run its checks, and demonstrate the reversed rules.
set -eu
cd "$(dirname "$0")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

echo "== build =="; go build ./...; echo "build ok"
echo; echo "== vet =="; go vet ./...; echo "vet ok"
echo; echo "== gofmt =="
un="$(gofmt -l internal cmd)"
[ -z "$un" ] || { echo "not gofmt-clean:"; echo "$un"; exit 1; }
echo "gofmt clean"
echo; echo "== tests =="; go test ./...
echo
go build -o "$WORK/poweramp-license" ./cmd/poweramp-license
echo "== the rules Poweramp applies =="
"$WORK/poweramp-license" rules
echo
echo "== the boundary, both sides =="
for r in 228 229 230 272 273; do "$WORK/poweramp-license" evaluate "$r" | head -1; done
echo
echo "all checks passed"
