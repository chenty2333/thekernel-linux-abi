#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
usercopy_dir="$repo_root/crates/usercopy"
process_dir="$repo_root/crates/process"

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
    "$usercopy_dir/Cargo.toml.orig"
check_sha256 \
    bce7bd9b92c903eccad380a9eb6a1da57005a24bea0618cd6828bdafe3eb48e9 \
    "$usercopy_dir/.cargo_vcs_info.json"
check_sha256 \
    58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd \
    "$usercopy_dir/LICENSE"

grep -Fq '3596dd192ef0b8c6790c5d3d1c69746c3f94afef46907a5314f1a478917daf53' \
    "$usercopy_dir/VENDOR.md"
grep -Fq '13a9296f82ce2d0fd1143cbabca3598948bfffd9' "$usercopy_dir/VENDOR.md"
grep -Fq 'dbbaea9ff0ee6c63bdfb9d9828d4a8d25ba8d0b1' "$usercopy_dir/VENDOR.md"

check_sha256 \
    c0a12a23f90b64b4ac43f31ed298c680896383014662b95979243ae8d91967d5 \
    "$process_dir/Cargo.toml.orig"
check_sha256 \
    41b72a2b6bf0faa83d0daf7d919a11ed96eb5c34a27cb243ddbe25df3c2cfd24 \
    "$process_dir/.cargo_vcs_info.json"
check_sha256 \
    cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30 \
    "$process_dir/LICENSE"

grep -Fq '88fa031a95c25b7bcfe8883f9f53238c9053a2a89f790bb1a7c35d080c6d3b65' \
    "$process_dir/VENDOR.md"
grep -Fq 'ab4fd0e8f91587ca18d3d2ab3e79dcf88b4200a8' "$process_dir/VENDOR.md"
grep -Fq 'ad905ce0f555026609fd874c6ef58fca6d510162' "$process_dir/VENDOR.md"
grep -Fq 'dbbaea9ff0ee6c63bdfb9d9828d4a8d25ba8d0b1' "$process_dir/VENDOR.md"

printf 'provenance: PASS\n'
