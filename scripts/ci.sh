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

cd "$repo_root"
run_cargo fmt --all -- --check
run_cargo clippy --workspace --all-targets --all-features -- -D warnings
run_cargo test --workspace --all-features
run_cargo check -p thekernel-linux-usercopy --no-default-features --lib

for target in riscv64gc-unknown-none-elf loongarch64-unknown-none; do
    run_cargo check -p thekernel-linux-usercopy --no-default-features --target "$target"
    run_cargo check -p thekernel-linux-usercopy --features alloc --target "$target"
done

"$script_dir/check-provenance.sh"
CARGO_TOOLCHAIN=${CARGO_TOOLCHAIN:-} \
PACKAGE_ALLOW_DIRTY=${PACKAGE_ALLOW_DIRTY:-0} \
    "$script_dir/test-package.sh"

printf 'workspace-ci: PASS\n'
