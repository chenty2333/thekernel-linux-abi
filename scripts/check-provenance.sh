#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
usercopy_dir="$repo_root/crates/usercopy"
process_dir="$repo_root/crates/process"
signal_dir="$repo_root/crates/signal"
vfs_dir="$repo_root/crates/vfs"
fd_dir="$repo_root/crates/fd"
cred_dir="$repo_root/crates/cred"
mm_dir="$repo_root/crates/mm"
io_uring_dir="$repo_root/crates/io-uring"
seccomp_dir="$repo_root/crates/seccomp"

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
    c623c05c243abb71faf51a8449fed0e535331cfea155e3835368944630efe345 \
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

check_sha256 \
    e0eaa00fb0430f9a29f19ea632bf3bce0a27cbf37536c1fa81054b10aae4ff53 \
    "$signal_dir/Cargo.toml.orig"
check_sha256 \
    4f0f5db3891f208616ae362c6ea0e0c63d7cc7ac2dc2b774c7b1b9a08171a11f \
    "$signal_dir/.cargo_vcs_info.json"
check_sha256 \
    58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd \
    "$signal_dir/LICENSE"

grep -Fq 'f72adf2bff529986c36c6b3920332afbefd0f6f6178855347f1bac15f4304d37' \
    "$signal_dir/VENDOR.md"
grep -Fq '0a39846c582895555816145f47f82ceb0c89aa62' "$signal_dir/VENDOR.md"
grep -Fq 'dbbaea9ff0ee6c63bdfb9d9828d4a8d25ba8d0b1' "$signal_dir/VENDOR.md"

check_sha256 \
    cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30 \
    "$vfs_dir/LICENSE"
grep -Fq 'dbbaea9ff0ee6c63bdfb9d9828d4a8d25ba8d0b1' "$vfs_dir/VENDOR.md"
grep -Fq '44696aa3a489d2baf58efa61b37833f100072bee' "$vfs_dir/VENDOR.md"
grep -Fq '62e22d7cfc1ca1c25bede6aaeca370c163a9a1ef' "$vfs_dir/VENDOR.md"
grep -Fq '5f5619c' "$vfs_dir/VENDOR.md"

check_sha256 \
    cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30 \
    "$fd_dir/LICENSE"
grep -Fq 'dbbaea9ff0ee6c63bdfb9d9828d4a8d25ba8d0b1' "$fd_dir/VENDOR.md"
grep -Fq '44696aa3a489d2baf58efa61b37833f100072bee' "$fd_dir/VENDOR.md"
grep -Fq '62e22d7cfc1ca1c25bede6aaeca370c163a9a1ef' "$fd_dir/VENDOR.md"
grep -Fq '3849af2' "$fd_dir/VENDOR.md"
grep -Fq 'cc09058dc94bd0c3599e3f5538a55a8981026af5' "$fd_dir/VENDOR.md"

check_sha256 \
    cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30 \
    "$cred_dir/LICENSE"
grep -Fq '38ed3c257e833a5d92c5246935adf071eb3df283' "$cred_dir/VENDOR.md"
grep -Fq 'c5207dc09b5524eb67c53d181c28dfdf696415b2' "$cred_dir/VENDOR.md"
grep -Fq 'dd3210c47e8d3ac6b4e9141fc68acc03b38c0ba3' "$cred_dir/VENDOR.md"
grep -Fq '86691d52a6d3796ad36ba474cf0a9493f6d99202' "$cred_dir/VENDOR.md"

check_sha256 \
    cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30 \
    "$mm_dir/LICENSE"
grep -Fq '0e24cb7acc37eab762db97b1dbdbb73924679a19' "$mm_dir/VENDOR.md"
grep -Fq '44696aa3a489d2baf58efa61b37833f100072bee' "$mm_dir/VENDOR.md"
grep -Fq '8fe57fc696e6ccd1d8f7f48959116d17db467eaa' "$mm_dir/VENDOR.md"
grep -Fq '37411049265056135a5e18c8c75a0c3d16b18579' "$mm_dir/VENDOR.md"

check_sha256 \
    cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30 \
    "$io_uring_dir/LICENSE"
grep -Fq 'f9e30c9f72e3f267621c2d36aafc83e65ab76568' "$io_uring_dir/VENDOR.md"
grep -Fq '783cd2c3dca8b6c434e955b84c20c8940588dc68' "$io_uring_dir/VENDOR.md"
grep -Fq '80272cbeb42bcd0b39a75685a50b0009b77cd380' "$io_uring_dir/VENDOR.md"
grep -Fq '435916bf0714a61e0fd1ebab5f6486532dedd8e4' "$io_uring_dir/VENDOR.md"

check_sha256 \
    cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30 \
    "$seccomp_dir/LICENSE"
grep -Fq '0c6d5e68acd274f2950ec1a66fdb7787f1ab291c' "$seccomp_dir/VENDOR.md"
grep -Fq 'a2b4f6f7e0bfbb1ca4bdf4fef45e104185749705' "$seccomp_dir/VENDOR.md"
grep -Fq '5c34536fd766b5f84f2fb8e6b18a2ab340659582' "$seccomp_dir/VENDOR.md"
grep -Fq 'adc218676eef25575469234709c2d87185ca223a' "$seccomp_dir/VENDOR.md"
grep -Fq \
    'axcbpf = { package = "thekernel-axcbpf", path = "../thekernel-ax/crates/thekernel-axcbpf", version = "=0.1.0" }' \
    "$repo_root/Cargo.toml"

printf 'provenance: PASS\n'
