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

ADB="${ADB:-/c/Program Files (x86)/Android/android-sdk/platform-tools/adb.exe}"
export MSYS2_ARG_CONV_EXCL='*'
REMOTE_DIR=/data/local/tmp
PRESSURE_FILE="$REMOTE_DIR/agm3_pressure.bin"
TEST_MARKER='TEST PASSED — PGD primitive verified'
WRITE_MARKER='IDEMPOTENT PGD WRITE VERIFIED'

usage() {
    cat <<'EOF'
Usage: scripts/agm3_adb.sh <command> [label]

  check                  Check ADB, exact firmware target, and /dev/mali0 access
  pressure               Create the dedicated 1536 MiB temporary pressure file
  test                   Run TEST_MODE and require the PGD success marker
  verify                 Require test success, then verify an idempotent PGD write
  shell                  Require both prior successes, then start interactive FULL
  bugreport [label]      Save a full bugreport locally under logs/ (private data)

Run check -> pressure -> test -> verify -> shell. Never run FULL as the first test.
The shell command intentionally has no timeout or automatic process cleanup.
EOF
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

require_adb() {
    command -v "$ADB" >/dev/null 2>&1 || fail "adb not found: $ADB; set ADB"
    "$ADB" get-state >/dev/null 2>&1 || fail "connect exactly one authorized device through ADB"
}

check_target() {
    require_adb
    local fingerprint patch
    fingerprint="$("$ADB" shell getprop ro.build.fingerprint | tr -d '\r')"
    patch="$("$ADB" shell getprop ro.build.version.security_patch | tr -d '\r')"
    [[ "$fingerprint" == *AGM3-W09HN* && "$fingerprint" == *11.0.2.197* ]] ||
        fail "unsupported fingerprint: $fingerprint"
    [[ "$patch" == 2022-04-01 ]] || fail "unsupported security patch: $patch"
    "$ADB" shell 'test -r /dev/mali0 && test -w /dev/mali0' >/dev/null 2>&1 ||
        fail '/dev/mali0 is not readable and writable by the ADB shell user'
    printf 'target: %s\nsecurity patch: %s\n' "$fingerprint" "$patch"
}

require_local_file() {
    [[ -s "$1" ]] || fail "$1 is missing; run scripts/build.sh first"
}

require_pressure() {
    "$ADB" shell "test -f $PRESSURE_FILE" >/dev/null 2>&1 ||
        fail "pressure file missing; run scripts/agm3_adb.sh pressure after checking free space"
}

require_log_marker() {
    [[ -f "$1" ]] && grep -Fq "$2" "$1" ||
        fail "$1 lacks the required success marker; complete the preceding stages on this target"
}

run_stage() {
    local binary="$1"
    local log="$2"
    local marker="$3"
    local name remote rc
    name="$(basename -- "$binary")"
    remote="$REMOTE_DIR/$name"
    require_local_file "$binary"
    require_pressure
    mkdir -p logs
    : >"$log"
    "$ADB" push "$binary" "$remote"
    "$ADB" shell "chmod 755 $remote"
    printf 'Running %s; success in the log alone is insufficient if the process fails.\n' "$name"
    set +e
    "$ADB" shell "PRESSURE_FILE=$PRESSURE_FILE timeout 120s $remote 1" 2>&1 | tee "$log"
    rc=${PIPESTATUS[0]}
    set -e
    ((rc == 0)) || fail "$name exited with status $rc; do not continue to FULL"
    grep -Fq "$marker" "$log" || fail "$name did not print: $marker"
    printf '%s passed; evidence saved to %s\n' "$name" "$log"
}

if (($# < 1 || $# > 2)); then
    usage >&2
    exit 2
fi

case "$1" in
    check)
        (($# == 1)) || fail 'check takes no label'
        check_target
        "$ADB" shell 'id; uname -a; getenforce || true; ls -l /dev/mali0; df -h /data/local/tmp'
        ;;
    pressure)
        (($# == 1)) || fail 'pressure takes no label'
        check_target
        printf 'This creates only %s (1536 MiB). Confirm sufficient free space.\n' "$PRESSURE_FILE"
        "$ADB" shell 'df -h /data/local/tmp'
        "$ADB" shell "dd if=/dev/zero of=$PRESSURE_FILE bs=1048576 count=1536; sync" || fail 'could not create pressure file; do not delete user data to make room'
        "$ADB" shell "ls -l $PRESSURE_FILE; df -h /data/local/tmp"
        ;;
    test)
        (($# == 1)) || fail 'test takes no label'
        check_target
        run_stage build/agm3_test_work logs/test.log "$TEST_MARKER"
        ;;
    verify)
        (($# == 1)) || fail 'verify takes no label'
        check_target
        require_log_marker logs/test.log "$TEST_MARKER"
        run_stage build/agm3_test_write_work logs/verify.log "$WRITE_MARKER"
        require_log_marker logs/verify.log "$TEST_MARKER"
        ;;
    shell)
        (($# == 1)) || fail 'shell takes no label'
        check_target
        require_log_marker logs/test.log "$TEST_MARKER"
        require_log_marker logs/verify.log "$WRITE_MARKER"
        require_log_marker logs/verify.log "$TEST_MARKER"
        require_local_file build/agm3_full_work
        require_pressure
        "$ADB" push build/agm3_full_work "$REMOTE_DIR/agm3_full_work"
        "$ADB" shell "chmod 755 $REMOTE_DIR/agm3_full_work"
        printf 'Starting interactive FULL without timeout. UID 0 is the root criterion.\n'
        printf 'Do not use Ctrl-C, kill -9, or an automatic cleanup on the Mali context.\n'
        "$ADB" shell "PRESSURE_FILE=$PRESSURE_FILE $REMOTE_DIR/agm3_full_work 1"
        ;;
    bugreport)
        label="${2:-failure}"
        [[ "$label" =~ ^[A-Za-z0-9_-]+$ ]] || fail 'label must contain only letters, digits, _ or -'
        require_adb
        mkdir -p logs
        output="logs/bugreport_${label}_$(date +%Y%m%d_%H%M%S).txt"
        "$ADB" shell /system/bin/bugreport >"$output" || fail "bugreport failed; partial output is in $output"
        printf 'Saved %s. It can contain private data: do not publish it.\n' "$output"
        ;;
    -h|--help|help)
        (($# == 1)) || fail 'help takes no label'
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
