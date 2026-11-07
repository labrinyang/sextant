#!/usr/bin/env sh
# Regenerates QuoteLens.bin — the runtime bytecode src/lens.rs embeds and
# injects via eth_call state override. Run after editing QuoteLens.sol.
set -e
cd "$(dirname "$0")"
forge build --root .
jq -r .deployedBytecode.object out/QuoteLens.sol/QuoteLens.json > QuoteLens.bin
wc -c QuoteLens.bin
