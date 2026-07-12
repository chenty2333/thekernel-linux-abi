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
    packages=(
        thekernel-linux-usercopy
        thekernel-linux-process
        thekernel-linux-signal
        thekernel-linux-vfs
        thekernel-linux-fd
    )
else
    packages=("$@")
fi

# The signal package intentionally depends on the unpublished usercopy release
# candidate. Test it against the packaged usercopy source, not the workspace
# checkout, including when signal is the only package requested.
needs_packaged_usercopy=0
for package in "${packages[@]}"; do
    case "$package" in
        thekernel-linux-signal)
            needs_packaged_usercopy=1
            ;;
    esac
done
if [ "$needs_packaged_usercopy" = 1 ]; then
    ordered_packages=(thekernel-linux-usercopy)
    for package in "${packages[@]}"; do
        if [ "$package" != thekernel-linux-usercopy ]; then
            ordered_packages+=("$package")
        fi
    done
    packages=("${ordered_packages[@]}")
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
        thekernel-linux-signal)
            version=0.1.0
            crate_path=crates/signal
            ;;
        thekernel-linux-vfs)
            version=0.1.0
            crate_path=crates/vfs
            ;;
        thekernel-linux-fd)
            version=0.1.0
            crate_path=crates/fd
            ;;
        *)
            printf 'unknown workspace package: %s\n' "$package" >&2
            exit 1
            ;;
    esac

    if [ "$package" = thekernel-linux-signal ]; then
        # Cargo's nightly workspace packager can assemble an unpublished
        # intra-workspace dependency and its consumer in one release set.
        # The explicit unpacked tests below replace Cargo's staging verifier.
        package_args=(
            -Z package-workspace
            package
            --locked
            --no-verify
            -p thekernel-linux-usercopy
            -p thekernel-linux-signal
        )
    else
        package_args=(package --locked -p "$package")
    fi
    if [ "${PACKAGE_ALLOW_DIRTY:-0}" = 1 ]; then
        package_args+=(--allow-dirty)
    fi
    if [ "$package" = thekernel-linux-signal ]; then
        packaged_usercopy_dir="$unpack_root/thekernel-linux-usercopy-0.1.0"
        [ -d "$packaged_usercopy_dir" ] || {
            printf 'packaged usercopy dependency missing: %s\n' \
                "$packaged_usercopy_dir" >&2
            exit 1
        }
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
    case "$package" in
        thekernel-linux-process|thekernel-linux-signal)
            ! grep -Fq 'rust-version' "$package_dir/Cargo.toml" || {
                printf '%s must not claim a stable rust-version\n' "$package" >&2
                exit 1
            }
            grep -Fq 'toolchain = "nightly-2025-05-20"' "$package_dir/Cargo.toml"
            grep -Fq 'nightly-features = ["allocator_api"]' "$package_dir/Cargo.toml"
            awk '
                $0 == "[dependencies.kspin]" { in_kspin = 1; next }
                in_kspin && /^\[/ { in_kspin = 0 }
                in_kspin && $0 == "features = [\"smp\"]" { found = 1 }
                END { exit(found ? 0 : 1) }
            ' "$package_dir/Cargo.toml" || {
                printf '%s packaged kspin dependency must enable smp\n' \
                    "$package" >&2
                exit 1
            }
            ;;
    esac

    "$script_dir/check-packaged-manifest.py" "$package_dir/Cargo.toml"

    unpacked_cargo_config=()
    if [ "$package" = thekernel-linux-signal ]; then
        grep -Fq 'thekernel-linux-usercopy' "$package_dir/Cargo.toml"
        unpacked_cargo_config=(
            --config
            "patch.crates-io.thekernel-linux-usercopy.path=\"$packaged_usercopy_dir\""
        )
    fi

    run_cargo test \
        --manifest-path "$package_dir/Cargo.toml" \
        --all-features \
        "${unpacked_cargo_config[@]}"
    run_cargo check \
        --manifest-path "$package_dir/Cargo.toml" \
        --no-default-features \
        --lib \
        "${unpacked_cargo_config[@]}"

    printf 'package-unpack: PASS (%s)\n' "$archive"
done
