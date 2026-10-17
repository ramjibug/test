#!/usr/bin/env bash
# Records the environment the evidence was produced in.
# Usage: ./capture_env.sh /path/to/wallet-core > ../logs/00-environment.log
set -u
WC="${1:?usage: capture_env.sh /path/to/wallet-core}"

echo "== date (UTC)";            date -u +"%Y-%m-%dT%H:%M:%SZ"
echo "== wallet-core commit";    git -C "$WC" log -1 --format='commit:  %H%ndate:    %ci%nsubject: %s'
echo "== local changes (git status --short)"; git -C "$WC" status --short | head -20
echo "== rustc -Vv";             rustc -Vv
echo "== cargo -V";              cargo -V
echo "== rust toolchain files";  for f in "$WC"/rust/rust-toolchain*; do [ -e "$f" ] && { echo "-- $f"; cat "$f"; }; done
echo "== rust/Cargo.toml [profile.release]"
awk '/^\[profile\.release\]/{p=1} p{print} p&&/^$/{exit}' "$WC/rust/Cargo.toml"
echo "== host";                  uname -srm
