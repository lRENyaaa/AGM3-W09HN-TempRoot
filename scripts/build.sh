#!/usr/bin/env bash
# Copyright 2026 lRENyaaa
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     https://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CLANG="${CLANG:-/c/Program Files (x86)/Android/AndroidNDK/android-ndk-r27c/toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe}"
SYSROOT="${SYSROOT:-C:/Program Files (x86)/Android/AndroidNDK/android-ndk-r27c/toolchains/llvm/prebuilt/windows-x86_64/sysroot}"
ADB="${ADB:-/c/Program Files (x86)/Android/android-sdk/platform-tools/adb.exe}"
export MSYS2_ARG_CONV_EXCL='*'
export CLANG SYSROOT ADB

command -v "$CLANG" >/dev/null 2>&1 || {
    printf 'error: clang not found: %s\nSet CLANG to the NDK clang executable.\n' "$CLANG" >&2
    exit 1
}
[[ -d "$SYSROOT" ]] || {
    printf 'error: sysroot not found: %s\nSet SYSROOT to the NDK sysroot directory.\n' "$SYSROOT" >&2
    exit 1
}

mkdir -p build
common_flags=(
    --target=aarch64-linux-android29
    "--sysroot=$SYSROOT"
    -Wall
    -Wextra
    -pthread
    -Isrc
)

build_binary() {
    local output="$1"
    shift
    "$CLANG" "${common_flags[@]}" "$@" src/honor_agm3.c -o "$output"
    printf 'built %s\n' "$output"
}

build_binary build/agm3_test_work -DSHELL -DTEST_MODE
build_binary build/agm3_test_write_work -DSHELL -DTEST_MODE -DVERIFY_PGD_WRITE
build_binary build/agm3_full_work -DSHELL

for artifact in build/agm3_test_work build/agm3_test_write_work build/agm3_full_work; do
    [[ -s "$artifact" ]] || {
        printf 'error: missing or empty build output: %s\n' "$artifact" >&2
        exit 1
    }
done
