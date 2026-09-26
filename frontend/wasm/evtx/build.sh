#!/usr/bin/env sh
# Builds the EVTX decoder the ingest worker loads (frontend/src/parsers/evtx/evtx.wasm).
#
# The toolchain is pinned (rust-toolchain.toml), the dependencies locked (Cargo.lock) and the build
# paths remapped, so the same source gives the same bytes on any machine: CI rebuilds it and fails
# when the committed file differs.
set -eu
cd "$(dirname "$0")"
here="$(pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="--cfg getrandom_backend=\"custom\" --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$here=/remn-evtx-wasm"
cargo build --release --locked --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/remn_evtx_wasm.wasm ../../src/parsers/evtx/evtx.wasm
sha256sum ../../src/parsers/evtx/evtx.wasm 2>/dev/null || shasum -a 256 ../../src/parsers/evtx/evtx.wasm
