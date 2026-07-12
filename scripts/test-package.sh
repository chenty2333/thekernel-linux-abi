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

if [ "$#" -eq 0 ]; then
    packages=(thekernel-linux-usercopy thekernel-linux-process)
else
    packages=("$@")
fi

unpack_root=$(mktemp -d)
trap 'rm -rf "$unpack_root"' EXIT

cd "$repo_root"
for package in "${packages[@]}"; do
    case "$package" in
        thekernel-linux-usercopy)
            version=0.1.0
            crate_path=crates/usercopy
            ;;
        thekernel-linux-process)
            version=0.1.0
            crate_path=crates/process
            ;;
        *)
            printf 'unknown workspace package: %s\n' "$package" >&2
            exit 1
            ;;
    esac

    package_args=(package --locked -p "$package")
    if [ "${PACKAGE_ALLOW_DIRTY:-0}" = 1 ]; then
        package_args+=(--allow-dirty)
    fi
    run_cargo "${package_args[@]}"

    archive="$repo_root/target/package/$package-$version.crate"
    [ -f "$archive" ] || {
        printf 'package archive missing: %s\n' "$archive" >&2
        exit 1
    }

    tar -xzf "$archive" -C "$unpack_root"
    package_dir="$unpack_root/$package-$version"

    for required in Cargo.toml CHANGELOG.md LICENSE NOTICE README.md VENDOR.md PATCHES.md; do
        [ -f "$package_dir/$required" ] || {
            printf '%s packaged file missing: %s\n' "$package" "$required" >&2
            exit 1
        }
    done

    # Cargo reserves these names and synthesizes package-local replacements.
    # Verify they describe this package rather than leaking the vendored
    # upstream records excluded by the source manifest.
    cmp -s "$repo_root/$crate_path/Cargo.toml" "$package_dir/Cargo.toml.orig" || {
        printf '%s Cargo.toml.orig is not the active crate manifest\n' "$package" >&2
        exit 1
    }

    if [ -f "$package_dir/.cargo_vcs_info.json" ]; then
        ! cmp -s \
            "$repo_root/$crate_path/.cargo_vcs_info.json" \
            "$package_dir/.cargo_vcs_info.json" || {
            printf '%s vendored upstream VCS record leaked into package\n' "$package" >&2
            exit 1
        }
        grep -Fq "\"path_in_vcs\": \"$crate_path\"" \
            "$package_dir/.cargo_vcs_info.json" || {
            printf '%s packaged VCS record has an unexpected source path\n' "$package" >&2
            exit 1
        }
    fi

    grep -Fq "name = \"$package\"" "$package_dir/Cargo.toml"
    grep -Fq 'license = "Apache-2.0"' "$package_dir/Cargo.toml"
    grep -Fq 'repository = "https://github.com/chenty2333/thekernel-linux-abi"' \
        "$package_dir/Cargo.toml"
    if [ "$package" = thekernel-linux-process ]; then
        ! grep -Fq 'rust-version' "$package_dir/Cargo.toml" || {
            printf '%s must not claim a stable rust-version\n' "$package" >&2
            exit 1
        }
        grep -Fq 'toolchain = "nightly-2025-05-20"' "$package_dir/Cargo.toml"
        grep -Fq 'nightly-features = ["allocator_api"]' "$package_dir/Cargo.toml"
    fi

    run_cargo test --manifest-path "$package_dir/Cargo.toml" --all-features
    run_cargo check --manifest-path "$package_dir/Cargo.toml" --no-default-features --lib

    printf 'package-unpack: PASS (%s)\n' "$archive"
done
