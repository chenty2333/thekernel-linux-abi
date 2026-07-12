#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)

run_cargo() {
    if [ -n "${CARGO_TOOLCHAIN:-}" ]; then
        cargo "+$CARGO_TOOLCHAIN" "$@"
    else
        cargo "$@"
    fi
}

case "${CARGO_TOOLCHAIN:-nightly-2025-05-20}" in
    stable|1.85|1.85.0)
        stable_only=1
        ;;
    *)
        stable_only=0
        ;;
esac

cd "$repo_root"
run_cargo fmt --all -- --check

if [ "$stable_only" = 1 ]; then
    for package in thekernel-linux-usercopy thekernel-linux-vfs thekernel-linux-fd; do
        run_cargo clippy -p "$package" --all-targets --all-features -- -D warnings
        run_cargo test -p "$package" --all-features
    done
else
    run_cargo clippy --workspace --all-targets --all-features -- -D warnings
    run_cargo test --workspace --all-features
    run_cargo check -p thekernel-linux-process --no-default-features --lib
    run_cargo check -p thekernel-linux-signal --no-default-features --lib
fi

run_cargo check -p thekernel-linux-usercopy --no-default-features --lib
run_cargo check -p thekernel-linux-vfs --no-default-features --lib
run_cargo check -p thekernel-linux-fd --no-default-features --lib
run_cargo check -p thekernel-linux-fd --features alloc --lib

for target in riscv64gc-unknown-none-elf loongarch64-unknown-none; do
    run_cargo check -p thekernel-linux-usercopy --no-default-features --target "$target"
    run_cargo check -p thekernel-linux-usercopy --features alloc --target "$target"
    run_cargo check -p thekernel-linux-vfs --no-default-features --target "$target"
    run_cargo check -p thekernel-linux-fd --no-default-features --target "$target"
    run_cargo check -p thekernel-linux-fd --features alloc --target "$target"
    if [ "$stable_only" = 0 ]; then
        run_cargo check -p thekernel-linux-process --no-default-features --target "$target"
        run_cargo check -p thekernel-linux-signal --features multitask --target "$target"
    fi
done

"$script_dir/check-provenance.sh"
if [ "$stable_only" = 1 ]; then
    package_list=(thekernel-linux-usercopy thekernel-linux-vfs thekernel-linux-fd)
else
    package_list=(
        thekernel-linux-usercopy
        thekernel-linux-process
        thekernel-linux-signal
        thekernel-linux-vfs
        thekernel-linux-fd
    )
fi
CARGO_TOOLCHAIN=${CARGO_TOOLCHAIN:-} \
PACKAGE_ALLOW_DIRTY=${PACKAGE_ALLOW_DIRTY:-0} \
    "$script_dir/test-package.sh" "${package_list[@]}"

printf 'workspace-ci: PASS\n'
