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
        thekernel-linux-cred
        thekernel-linux-mm
        thekernel-linux-io-uring
        thekernel-linux-seccomp
    )
else
    packages=("$@")
fi

# The signal package intentionally depends on the unpublished usercopy release
# candidate. Test it against the packaged usercopy source, not the workspace
# checkout, including when signal is the only package requested.
needs_packaged_usercopy=0
needs_packaged_axcbpf=0
for package in "${packages[@]}"; do
    case "$package" in
        thekernel-linux-signal)
            needs_packaged_usercopy=1
            ;;
        thekernel-linux-seccomp)
            needs_packaged_axcbpf=1
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

if [ "$needs_packaged_axcbpf" = 1 ]; then
    axcbpf_repo=${AXCBPF_SOURCE_ROOT:-"$repo_root/../thekernel-ax"}
    axcbpf_crate_path=crates/thekernel-axcbpf
    axcbpf_source="$axcbpf_repo/$axcbpf_crate_path"
    axcbpf_reviewed_commit=a2b4f6f7e0bfbb1ca4bdf4fef45e104185749705
    axcbpf_release_commit=5c34536fd766b5f84f2fb8e6b18a2ab340659582

    [ -d "$axcbpf_source" ] || {
        printf 'thekernel-axcbpf source missing: %s\n' "$axcbpf_source" >&2
        exit 1
    }
    for commit in "$axcbpf_reviewed_commit" "$axcbpf_release_commit"; do
        git -C "$axcbpf_repo" cat-file -e "$commit^{commit}" || {
            printf 'thekernel-axcbpf source commit missing: %s\n' "$commit" >&2
            exit 1
        }
    done
    git -C "$axcbpf_repo" diff --quiet \
        "$axcbpf_reviewed_commit" "$axcbpf_release_commit" -- \
        "$axcbpf_crate_path" || {
        printf '%s\n' \
            'thekernel-axcbpf release commit changes the reviewed 0.1.0 crate tree' >&2
        exit 1
    }
    git -C "$axcbpf_repo" diff --quiet \
        "$axcbpf_release_commit" -- "$axcbpf_crate_path" || {
        printf '%s\n' \
            'thekernel-axcbpf source differs from the exact 0.1.0 release commit' >&2
        exit 1
    }
    if [ -n "$(git -C "$axcbpf_repo" ls-files --others --exclude-standard -- "$axcbpf_crate_path")" ]; then
        printf '%s\n' \
            'thekernel-axcbpf source contains untracked package files' >&2
        exit 1
    fi

    if ! git -C "$repo_root" diff --quiet HEAD -- Cargo.toml crates/seccomp \
        || [ -n "$(git -C "$repo_root" ls-files --others --exclude-standard -- crates/seccomp)" ]; then
        if [ "${PACKAGE_ALLOW_DIRTY:-0}" != 1 ]; then
            printf '%s\n' \
                'seccomp package staging requires clean release sources; set PACKAGE_ALLOW_DIRTY=1 only for development checks' >&2
            exit 1
        fi
    fi

    if ! git -C "$axcbpf_repo" diff --quiet HEAD \
        || ! git -C "$axcbpf_repo" diff --cached --quiet \
        || [ -n "$(git -C "$axcbpf_repo" ls-files --others --exclude-standard)" ]; then
        printf '%s\n' \
            'thekernel-axcbpf package archive requires a clean reviewed worktree' >&2
        exit 1
    fi

    # Produce the dependency from its real Git checkout, preserving Cargo's
    # package-local VCS record. This is the same archive identity that an
    # authorized clean release would upload, not a synthetic source copy.
    axcbpf_package_toolchain=1.85.0
    axcbpf_package_target="$unpack_root/axcbpf-package-target"
    CARGO_TARGET_DIR="$axcbpf_package_target" \
        cargo "+$axcbpf_package_toolchain" package \
            --manifest-path "$axcbpf_repo/Cargo.toml" \
            --locked \
            -p thekernel-axcbpf
    packaged_axcbpf_archive="$axcbpf_package_target/package/thekernel-axcbpf-0.1.0.crate"
    [ -f "$packaged_axcbpf_archive" ] || {
        printf 'thekernel-axcbpf package archive missing: %s\n' \
            "$packaged_axcbpf_archive" >&2
        exit 1
    }

    tar -xzf "$packaged_axcbpf_archive" -C "$unpack_root"
    packaged_axcbpf_dir="$unpack_root/thekernel-axcbpf-0.1.0"
    for required in \
        Cargo.toml Cargo.toml.orig .cargo_vcs_info.json CHANGELOG.md README.md \
        LICENSES/Apache-2.0.txt src/lib.rs; do
        [ -f "$packaged_axcbpf_dir/$required" ] || {
            printf 'thekernel-axcbpf packaged file missing: %s\n' "$required" >&2
            exit 1
        }
    done
    cmp -s "$axcbpf_source/Cargo.toml" "$packaged_axcbpf_dir/Cargo.toml.orig" || {
        printf '%s\n' \
            'thekernel-axcbpf Cargo.toml.orig is not the reviewed source manifest' >&2
        exit 1
    }
    grep -Fq 'name = "thekernel-axcbpf"' "$packaged_axcbpf_dir/Cargo.toml"
    grep -Fq 'version = "0.1.0"' "$packaged_axcbpf_dir/Cargo.toml"
    grep -Fq 'license = "Apache-2.0"' "$packaged_axcbpf_dir/Cargo.toml"
    grep -Fq 'repository = "https://github.com/chenty2333/thekernel-ax"' \
        "$packaged_axcbpf_dir/Cargo.toml"
    grep -Fq "\"sha1\": \"$axcbpf_release_commit\"" \
        "$packaged_axcbpf_dir/.cargo_vcs_info.json"
    ! grep -Fq '"dirty": true' "$packaged_axcbpf_dir/.cargo_vcs_info.json" || {
        printf '%s\n' 'thekernel-axcbpf packaged VCS record is dirty' >&2
        exit 1
    }
    grep -Fq '"path_in_vcs": "crates/thekernel-axcbpf"' \
        "$packaged_axcbpf_dir/.cargo_vcs_info.json"
    "$script_dir/check-packaged-manifest.py" "$packaged_axcbpf_dir/Cargo.toml"

    # Cargo package checks registry availability even with --no-verify. Build
    # a temporary directory source for all locked registry dependencies and
    # add the exact packaged axcbpf archive with its real archive checksum.
    # The source replacement is used only while assembling this local archive;
    # the normalized seccomp manifest and lock still name crates.io.
    package_vendor="$unpack_root/package-vendor"
    if ! vendor_output=$(run_cargo vendor \
        --manifest-path "$repo_root/Cargo.toml" \
        --locked \
        --versioned-dirs \
        "$package_vendor" 2>&1); then
        printf '%s\n' "$vendor_output" >&2
        exit 1
    fi
    tar -xzf "$packaged_axcbpf_archive" -C "$package_vendor"
    vendored_axcbpf="$package_vendor/thekernel-axcbpf-0.1.0"
    python3 - "$vendored_axcbpf" "$packaged_axcbpf_archive" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
archive = pathlib.Path(sys.argv[2])
files = {
    path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted(root.rglob("*"))
    if path.is_file() and path.name != ".cargo-checksum.json"
}
checksum = {
    "files": files,
    "package": hashlib.sha256(archive.read_bytes()).hexdigest(),
}
(root / ".cargo-checksum.json").write_text(
    json.dumps(checksum, sort_keys=True, separators=(",", ":"))
)
PY

    package_source_config=(
        --config
        'source.crates-io.replace-with="local-packages"'
        --config
        "source.local-packages.directory=\"$package_vendor\""
    )
    seccomp_package_target="$unpack_root/seccomp-package-target"
    seccomp_package_args=(
        package
        --locked
        --offline
        --no-verify
        -p thekernel-linux-seccomp
    )
    if [ "${PACKAGE_ALLOW_DIRTY:-0}" = 1 ]; then
        seccomp_package_args+=(--allow-dirty)
    fi
    CARGO_TARGET_DIR="$seccomp_package_target" \
        run_cargo \
            "${seccomp_package_args[@]}" \
            "${package_source_config[@]}"
    seccomp_archive="$seccomp_package_target/package/thekernel-linux-seccomp-0.1.0.crate"
    [ -f "$seccomp_archive" ] || {
        printf 'seccomp package archive missing: %s\n' "$seccomp_archive" >&2
        exit 1
    }
fi

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
        thekernel-linux-cred)
            version=0.1.0
            crate_path=crates/cred
            ;;
        thekernel-linux-mm)
            version=0.1.0
            crate_path=crates/mm
            ;;
        thekernel-linux-io-uring)
            version=0.1.0
            crate_path=crates/io-uring
            ;;
        thekernel-linux-seccomp)
            version=0.1.0
            crate_path=crates/seccomp
            ;;
        *)
            printf 'unknown workspace package: %s\n' "$package" >&2
            exit 1
            ;;
    esac

    if [ "$package" = thekernel-linux-seccomp ]; then
        # This archive was produced together with the exact external
        # thekernel-axcbpf package above. Its unpacked compile is the verifier.
        package_args=()
    elif [ "$package" = thekernel-linux-signal ]; then
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
    if [ "$package" != thekernel-linux-seccomp ] \
        && [ "${PACKAGE_ALLOW_DIRTY:-0}" = 1 ]; then
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
    if [ "$package" = thekernel-linux-seccomp ]; then
        archive="$seccomp_archive"
    else
        run_cargo "${package_args[@]}"
        archive="$repo_root/target/package/$package-$version.crate"
    fi
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
        thekernel-linux-process|thekernel-linux-signal|thekernel-linux-cred|thekernel-linux-seccomp)
            ! grep -Fq 'rust-version' "$package_dir/Cargo.toml" || {
                printf '%s must not claim a stable rust-version\n' "$package" >&2
                exit 1
            }
            grep -Fq 'toolchain = "nightly-2025-05-20"' "$package_dir/Cargo.toml"
            grep -Fq 'nightly-features = ["allocator_api"]' "$package_dir/Cargo.toml"
            ;;
    esac
    case "$package" in
        thekernel-linux-process|thekernel-linux-signal)
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

    if [ "$package" = thekernel-linux-seccomp ]; then
        python3 - \
            "$package_dir/Cargo.toml" \
            "$package_dir/Cargo.lock" \
            "$packaged_axcbpf_archive" <<'PY'
import hashlib
import pathlib
import sys
import tomllib

manifest = tomllib.loads(pathlib.Path(sys.argv[1]).read_text())
dependency = manifest.get("dependencies", {}).get("axcbpf")
expected = {
    "package": "thekernel-axcbpf",
    "version": "=0.1.0",
}
if not isinstance(dependency, dict):
    raise SystemExit("seccomp packaged manifest has no structured axcbpf dependency")
for key, value in expected.items():
    if dependency.get(key) != value:
        raise SystemExit(
            f"seccomp packaged axcbpf {key} is {dependency.get(key)!r}, expected {value!r}"
        )
for forbidden in ("path", "git", "workspace"):
    if forbidden in dependency:
        raise SystemExit(f"seccomp packaged axcbpf dependency leaks {forbidden}")

lock = tomllib.loads(pathlib.Path(sys.argv[2]).read_text())
matches = [
    package
    for package in lock.get("package", [])
    if package.get("name") == "thekernel-axcbpf"
    and package.get("version") == "0.1.0"
]
if len(matches) != 1:
    raise SystemExit(
        f"seccomp release lock expected one thekernel-axcbpf 0.1.0, found {len(matches)}"
    )
locked = matches[0]
expected_source = "registry+https://github.com/rust-lang/crates.io-index"
if locked.get("source") != expected_source:
    raise SystemExit(
        f"seccomp release lock source is {locked.get('source')!r}, expected {expected_source!r}"
    )
archive_checksum = hashlib.sha256(pathlib.Path(sys.argv[3]).read_bytes()).hexdigest()
if locked.get("checksum") != archive_checksum:
    raise SystemExit(
        "seccomp release lock checksum does not match the coordinated "
        "thekernel-axcbpf archive"
    )
PY
    fi

    unpacked_cargo_config=()
    unpacked_cargo_args=()
    if [ "$package" = thekernel-linux-signal ]; then
        grep -Fq 'thekernel-linux-usercopy' "$package_dir/Cargo.toml"
        unpacked_cargo_config=(
            --config
            "patch.crates-io.thekernel-linux-usercopy.path=\"$packaged_usercopy_dir\""
        )
    elif [ "$package" = thekernel-linux-seccomp ]; then
        packaged_seccomp_lock="$unpack_root/seccomp-registry.lock"
        cp "$package_dir/Cargo.lock" "$packaged_seccomp_lock"
        unpacked_cargo_config=(
            --config
            "patch.crates-io.thekernel-axcbpf.path=\"$packaged_axcbpf_dir\""
        )
        run_cargo update \
            --manifest-path "$package_dir/Cargo.toml" \
            --offline \
            -p thekernel-axcbpf \
            "${unpacked_cargo_config[@]}"
        python3 - "$packaged_seccomp_lock" "$package_dir/Cargo.lock" <<'PY'
import pathlib
import sys
import tomllib

target = ("thekernel-axcbpf", "0.1.0")


def normalized(path: str):
    data = tomllib.loads(pathlib.Path(path).read_text())
    lock_version = data.pop("version", None)
    found = False
    for package in data.get("package", []):
        identity = (package.get("name"), package.get("version"))
        if identity == target:
            found = True
            package.pop("source", None)
            package.pop("checksum", None)
    if not found:
        raise SystemExit(f"{path}: missing thekernel-axcbpf 0.1.0 lock entry")
    return lock_version, data


before_version, before = normalized(sys.argv[1])
after_version, after = normalized(sys.argv[2])
if before_version != after_version and (before_version, after_version) != (3, 4):
    raise SystemExit(
        f"unexpected pre-publication lock format change: {before_version} -> {after_version}"
    )
if before != after:
    raise SystemExit(
        "pre-publication artifact patch changed lock data beyond "
        "thekernel-axcbpf source/checksum"
    )
PY
        unpacked_cargo_args=(--locked --offline)
    fi

    run_cargo test \
        --manifest-path "$package_dir/Cargo.toml" \
        --all-features \
        "${unpacked_cargo_args[@]}" \
        "${unpacked_cargo_config[@]}"
    run_cargo check \
        --manifest-path "$package_dir/Cargo.toml" \
        --no-default-features \
        --lib \
        "${unpacked_cargo_args[@]}" \
        "${unpacked_cargo_config[@]}"

    printf 'package-unpack: PASS (%s)\n' "$archive"
done
