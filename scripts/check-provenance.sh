#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
crate_dir="$repo_root/crates/usercopy"

check_sha256() {
    local expected=$1
    local path=$2
    local actual
    actual=$(sha256sum "$path" | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
        printf 'provenance checksum mismatch: %s\nexpected: %s\nactual:   %s\n' \
            "$path" "$expected" "$actual" >&2
        return 1
    fi
}

check_sha256 \
    8573823b18252e8c8da10e1bc1c7a20cee27057c5d159027715da797a73015e2 \
    "$crate_dir/Cargo.toml.orig"
check_sha256 \
    bce7bd9b92c903eccad380a9eb6a1da57005a24bea0618cd6828bdafe3eb48e9 \
    "$crate_dir/.cargo_vcs_info.json"
check_sha256 \
    58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd \
    "$crate_dir/LICENSE"

grep -Fq '3596dd192ef0b8c6790c5d3d1c69746c3f94afef46907a5314f1a478917daf53' \
    "$crate_dir/VENDOR.md"
grep -Fq '13a9296f82ce2d0fd1143cbabca3598948bfffd9' "$crate_dir/VENDOR.md"
grep -Fq 'dbbaea9ff0ee6c63bdfb9d9828d4a8d25ba8d0b1' "$crate_dir/VENDOR.md"

printf 'provenance: PASS\n'
