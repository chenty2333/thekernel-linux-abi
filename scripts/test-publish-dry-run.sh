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
        thekernel-linux-vfs
        thekernel-linux-fd
        thekernel-linux-cred
        thekernel-linux-mm
        thekernel-linux-io-uring
    )
else
    packages=("$@")
fi

publish_args=(publish --dry-run --locked)
if [ "${PUBLISH_ALLOW_DIRTY:-0}" = 1 ]; then
    publish_args+=(--allow-dirty)
fi

cd "$repo_root"
for package in "${packages[@]}"; do
    case "$package" in
        thekernel-linux-usercopy|thekernel-linux-process|thekernel-linux-vfs|thekernel-linux-fd|thekernel-linux-cred|thekernel-linux-mm|thekernel-linux-io-uring)
            ;;
        thekernel-linux-seccomp)
            if [ "${AXCBPF_REGISTRY_READY:-0}" != 1 ]; then
                printf '%s\n' \
                    'seccomp registry dry-run is deferred until thekernel-axcbpf 0.1.0 is visible; set AXCBPF_REGISTRY_READY=1 only after checking the registry' >&2
                exit 1
            fi
            ;;
        thekernel-linux-signal)
            if [ "${SIGNAL_REGISTRY_READY:-0}" != 1 ]; then
                printf '%s\n' \
                    'signal registry dry-run is deferred until usercopy 0.1.0 is visible; set SIGNAL_REGISTRY_READY=1 only after checking the registry' >&2
                exit 1
            fi
            ;;
        *)
            printf 'unknown workspace package: %s\n' "$package" >&2
            exit 1
            ;;
    esac
    run_cargo "${publish_args[@]}" -p "$package"
    printf 'publish-dry-run: PASS (%s)\n' "$package"
done
