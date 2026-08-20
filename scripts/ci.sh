#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
AXCBPF_SOURCE_ROOT=${AXCBPF_SOURCE_ROOT:-$ROOT/../thekernel-ax}
cd "$ROOT"

usage() {
    cat <<'USAGE'
Usage: scripts/ci.sh [quality|msrv|all|release]

  quality  Nightly workspace format, lint, test, no_std, and provenance gate.
  msrv     Rust 1.85 checks for crates that claim stable/MSRV support.
  all      Run quality and msrv (the pull-request gate).
  release  Run all, rustdoc, package checks, and publish dry-runs.

The default command is all.
USAGE
}

step() {
    local name=$1
    shift
    printf '\n==> %s\n' "$name"
    "$@"
}

stable_packages=(
    thekernel-linux-usercopy
    thekernel-linux-vfs
    thekernel-linux-fd
    thekernel-linux-mm
    thekernel-linux-io-uring
    thekernel-linux-packet
    thekernel-linux-rseq
)

nightly_packages=(
    thekernel-linux-process
    thekernel-linux-signal
    thekernel-linux-cred
    thekernel-linux-seccomp
)

no_std_packages=(
    thekernel-linux-usercopy
    thekernel-linux-vfs
    thekernel-linux-fd
    thekernel-linux-mm
    thekernel-linux-io-uring
    thekernel-linux-packet
    thekernel-linux-rseq
    thekernel-linux-process
    thekernel-linux-signal
    thekernel-linux-cred
    thekernel-linux-seccomp
)

quality() {
    step 'rustfmt' cargo +nightly fmt --all -- --check
    step 'workspace clippy' \
        cargo +nightly clippy --workspace --all-targets --all-features \
        --locked -- -D warnings
    step 'workspace tests' \
        cargo +nightly test --workspace --all-features --locked

    local package
    for package in "${no_std_packages[@]}"; do
        step "$package no-default-features" \
            cargo +nightly check -p "$package" --no-default-features --lib --locked
    done
    step 'fd alloc-only configuration' \
        cargo +nightly check -p thekernel-linux-fd --features alloc --lib --locked
    step 'source provenance' scripts/check-provenance.sh
}

msrv() {
    local package
    for package in "${stable_packages[@]}"; do
        step "$package MSRV tests" \
            cargo +1.85.0 test -p "$package" --all-targets --all-features --locked
        step "$package MSRV clippy" \
            cargo +1.85.0 clippy -p "$package" --all-targets --all-features \
            --locked -- -D warnings
        step "$package MSRV no-default-features" \
            cargo +1.85.0 check -p "$package" --no-default-features --lib --locked
    done
    step 'fd MSRV alloc-only configuration' \
        cargo +1.85.0 check -p thekernel-linux-fd --features alloc --lib --locked
}

release() {
    quality
    msrv

    local package
    for package in "${stable_packages[@]}"; do
        step "$package MSRV rustdoc" \
            env RUSTDOCFLAGS='-D warnings' \
            cargo +1.85.0 doc -p "$package" --all-features --no-deps --locked
    done
    for package in "${nightly_packages[@]}"; do
        step "$package nightly rustdoc" \
            env RUSTDOCFLAGS='-D warnings' \
            cargo +nightly doc -p "$package" --all-features --no-deps --locked
    done

    # Keep release-only packaging mechanics out of pull requests. These lists
    # match the packages currently supported by the repository's package tools.
    step 'stable package artifacts' \
        env CARGO_TOOLCHAIN=1.85.0 \
        scripts/test-package.sh \
        thekernel-linux-usercopy \
        thekernel-linux-vfs \
        thekernel-linux-fd \
        thekernel-linux-mm \
        thekernel-linux-io-uring \
        thekernel-linux-packet
    step 'nightly package artifacts' \
        env CARGO_TOOLCHAIN=nightly \
        AXCBPF_SOURCE_ROOT="$AXCBPF_SOURCE_ROOT" \
        scripts/test-package.sh \
        thekernel-linux-process \
        thekernel-linux-signal \
        thekernel-linux-cred \
        thekernel-linux-seccomp

    step 'stable publish dry-runs' \
        env CARGO_TOOLCHAIN=1.85.0 \
        scripts/test-publish-dry-run.sh \
        thekernel-linux-usercopy \
        thekernel-linux-vfs \
        thekernel-linux-fd \
        thekernel-linux-mm \
        thekernel-linux-io-uring \
        thekernel-linux-packet
    step 'nightly publish dry-runs' \
        env CARGO_TOOLCHAIN=nightly \
        scripts/test-publish-dry-run.sh \
        thekernel-linux-process \
        thekernel-linux-cred
}

command=${1:-all}
if [ "$#" -gt 0 ]; then
    shift
fi
case "$command" in
    quality)
        [ "$#" -eq 0 ] || { usage >&2; exit 2; }
        quality
        ;;
    msrv)
        [ "$#" -eq 0 ] || { usage >&2; exit 2; }
        msrv
        ;;
    all)
        [ "$#" -eq 0 ] || { usage >&2; exit 2; }
        quality
        msrv
        ;;
    release)
        [ "$#" -eq 0 ] || { usage >&2; exit 2; }
        release
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
