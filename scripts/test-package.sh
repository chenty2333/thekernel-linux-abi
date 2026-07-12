#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
package=thekernel-linux-usercopy
version=0.1.0

run_cargo() {
    if [ -n "${CARGO_TOOLCHAIN:-}" ]; then
        cargo "+$CARGO_TOOLCHAIN" "$@"
    else
        cargo "$@"
    fi
}

package_args=(package --locked -p "$package")
if [ "${PACKAGE_ALLOW_DIRTY:-0}" = 1 ]; then
    package_args+=(--allow-dirty)
fi

cd "$repo_root"
run_cargo "${package_args[@]}"

archive="$repo_root/target/package/$package-$version.crate"
[ -f "$archive" ] || {
    printf 'package archive missing: %s\n' "$archive" >&2
    exit 1
}

unpack_dir=$(mktemp -d)
trap 'rm -rf "$unpack_dir"' EXIT
tar -xzf "$archive" -C "$unpack_dir"
package_dir="$unpack_dir/$package-$version"

for required in Cargo.toml LICENSE NOTICE README.md VENDOR.md PATCHES.md; do
    [ -f "$package_dir/$required" ] || {
        printf 'packaged file missing: %s\n' "$required" >&2
        exit 1
    }
done

# Cargo reserves these two names and synthesizes package-local replacements:
# Cargo.toml.orig is the active, pre-normalization package manifest, while
# .cargo_vcs_info.json describes this repository revision. The source-level
# `exclude` entries prevent our vendored upstream records from being selected;
# verify that the archive contains Cargo's replacements rather than those
# repository-only records.
cmp -s "$repo_root/crates/usercopy/Cargo.toml" "$package_dir/Cargo.toml.orig" || {
    printf 'packaged Cargo.toml.orig is not the active crate manifest\n' >&2
    exit 1
}

if [ -f "$package_dir/.cargo_vcs_info.json" ]; then
    ! cmp -s \
        "$repo_root/crates/usercopy/.cargo_vcs_info.json" \
        "$package_dir/.cargo_vcs_info.json" || {
        printf 'vendored upstream .cargo_vcs_info.json leaked into package\n' >&2
        exit 1
    }
    grep -Fq '"path_in_vcs": "crates/usercopy"' \
        "$package_dir/.cargo_vcs_info.json" || {
        printf 'packaged .cargo_vcs_info.json has an unexpected source path\n' >&2
        exit 1
    }
fi

grep -Fq 'name = "thekernel-linux-usercopy"' "$package_dir/Cargo.toml"
grep -Fq 'license = "Apache-2.0"' "$package_dir/Cargo.toml"
grep -Fq 'repository = "https://github.com/chenty2333/thekernel-linux-abi"' \
    "$package_dir/Cargo.toml"

run_cargo test --manifest-path "$package_dir/Cargo.toml" --all-features
run_cargo check --manifest-path "$package_dir/Cargo.toml" --no-default-features --lib

printf 'package-unpack: PASS (%s)\n' "$archive"
