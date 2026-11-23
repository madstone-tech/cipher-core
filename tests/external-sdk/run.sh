#!/usr/bin/env bash
# Consumer proof: pkg/cipher is consumable from a module OUTSIDE this module,
# and what the SDK writes is decryptable by the mdstn-cipher CLI built from
# this repo — module seam compatibility, not just self-consistency.
#
# A throwaway module in tests/external-sdk imports ONLY
# github.com/madstone-tech/cipher-core/pkg/cipher plus stdlib. If any step
# needed an internal/ path, Go's internal-visibility rule would refuse to
# compile it from that separate module — the failure mode this harness
# catches cheaply.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "==> building mdstn-cipher (CLI from this repo)"
CLI="$(mktemp -d)/mdstn-cipher"
(cd "$repo_root" && go build -o "$CLI" ./cmd/mdstn-cipher)

echo "==> running the external consumer module (SDK surface only)"
workdir="$(mktemp -d)"
# The CLI binary must survive the trap cleanup below.
trap 'rm -rf "$workdir"' EXIT
export EXTERNAL_SDK_OUT="$workdir/from-sdk.mdstn"
# The consumer makes a random file password at runtime and writes it here.
export EXTERNAL_SDK_PASSWORD_OUT="$workdir/from-sdk.password"
(cd "$repo_root/tests/external-sdk" && go run .)

echo "==> verifying the CLI decrypts the SDK's output"
"$CLI" decrypt "$EXTERNAL_SDK_OUT" \
  --passphrase "$(<"$EXTERNAL_SDK_PASSWORD_OUT")" \
  --output "$workdir/from-cli.txt"

if ! grep -q "external module round-trip payload" "$workdir/from-cli.txt"; then
  echo "ERROR: the CLI decrypted the SDK container but the plaintext did not match" >&2
  exit 1
fi

echo "external-sdk: SDK/CLI module compatibility OK"