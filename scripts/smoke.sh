#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

BUILD="${1:-build}"

TARGET="$BUILD/examples/target"
EXAMPLE="$BUILD/examples/controller_example"

if [[ ! -x "$TARGET" || ! -x "$EXAMPLE" ]]; then
    echo "missing build outputs; run make first" >&2
    exit 1
fi

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "== build outputs"
for f in "$BUILD/libvm_stowaway.a" \
         "$BUILD/libvm_stowaway_payload.dylib" \
         "$BUILD/libvm_stowaway_machshim.dylib" \
         "$BUILD/vm_stowaway" \
         "$TARGET" \
         "$BUILD/examples/mach_client"; do
    [[ -e "$f" ]] || fail "missing $f"
done

echo "== DYLD_INSERT_LIBRARIES backend"
OUTPUT=$("$EXAMPLE" "$TARGET" 5 2>&1 || true)
echo "$OUTPUT" | sed 's/^/    /'
echo "$OUTPUT" | grep -q "after:  secret=1337 message=rewritten from outside" \
    || fail "DYLD path: post-write values not observed"

echo "== LC_LOAD_DYLIB patcher backend"
PATCHED=$(mktemp -t vmsw-target.XXXXXX)
cp "$TARGET" "$PATCHED"
chmod +x "$PATCHED"
"$BUILD/vm_stowaway" patch "$PATCHED" "$PWD/$BUILD/libvm_stowaway_payload.dylib" \
    2>&1 | sed 's/^/    /'

"$PATCHED" 15 > "$PATCHED.out" 2>&1 &
TPID=$!
disown 2>/dev/null || true
trap '{ kill $TPID 2>/dev/null; wait $TPID 2>/dev/null; rm -f "$PATCHED" "$PATCHED.out"; } >/dev/null 2>&1 || :' EXIT
sleep 1

ADDR=$("$BUILD/vm_stowaway" resolve $TPID secret 2>/dev/null)
[[ -n "$ADDR" ]] || fail "resolve failed"
echo "    secret at $ADDR"
"$BUILD/vm_stowaway" write $TPID $ADDR "39050000" | sed 's/^/    /'
sleep 2
grep -q "secret=1337" "$PATCHED.out" || {
    sed 's/^/    /' < "$PATCHED.out"
    fail "patcher path: target never observed new value"
}

echo "== mach API shim (DYLD_INTERPOSE)"
PATCHED2=$(mktemp -t vmsw-shimtest.XXXXXX)
cp "$TARGET" "$PATCHED2"
chmod +x "$PATCHED2"
"$BUILD/vm_stowaway" patch "$PATCHED2" "$PWD/$BUILD/libvm_stowaway_payload.dylib" \
    >/dev/null 2>&1
"$PATCHED2" 20 > "$PATCHED2.out" 2>&1 &
T2=$!
disown 2>/dev/null || true
trap '{ kill $T2 2>/dev/null; wait $T2 2>/dev/null; rm -f "$PATCHED2" "$PATCHED2.out"; } >/dev/null 2>&1 || :' EXIT
sleep 1

SECRET=$("$BUILD/vm_stowaway" resolve $T2 secret 2>/dev/null)
echo "    secret @ $SECRET"
OUT=$("$BUILD/vm_stowaway" wrap --pid $T2 -- \
    "$BUILD/examples/mach_client" $T2 $SECRET 4 "39050000" 2>&1)
echo "$OUT" | sed 's/^/    /'
sleep 2

want() { echo "$OUT" | grep -q "$1" || fail "shim: $2"; }
grep -q "secret=1337" "$PATCHED2.out" || fail "target never observed write"
want "wrote 4 bytes"             "no write ack"
want "^region:"                  "no region walked"
want "dyld_all_image_infos @ 0x" "no TASK_DYLD_INFO"
want "task_basic_info: vsz="     "no TASK_BASIC_INFO"
want "^task_threads: "           "no task_threads"
want " pc=0x"                    "no thread_get_state"
want 'alloc/rt:.*round-trip'     "no alloc round-trip"
want "^pid_for_task: "           "no pid_for_task"
want "^vm_read_overwrite: "      "no legacy vm_read"
want "^thread_info: ok"          "no thread_info"

echo "== new ops: call, break, diff, unpatch"
PATCHED3=$(mktemp -t vmsw-newops.XXXXXX)
cp "$TARGET" "$PATCHED3"
chmod +x "$PATCHED3"
"$BUILD/vm_stowaway" patch "$PATCHED3" "$PWD/$BUILD/libvm_stowaway_payload.dylib" \
    >/dev/null 2>&1
"$PATCHED3" 30 > "$PATCHED3.out" 2>&1 &
T3=$!
disown 2>/dev/null || true
trap '{ kill $T3 2>/dev/null; wait $T3 2>/dev/null; rm -f "$PATCHED3" "$PATCHED3.out"; } >/dev/null 2>&1 || :' EXIT
sleep 1

GETPID=$("$BUILD/vm_stowaway" resolve $T3 libsystem_c.dylib getpid 2>/dev/null)
[[ -n "$GETPID" ]] || fail "resolve getpid"
RET=$("$BUILD/vm_stowaway" call $T3 $GETPID 2>&1)
echo "    call getpid -> $RET"
EXPECTED=$(printf "0x%x" $T3)
[[ "$RET" == "$EXPECTED" ]] || fail "call: expected $EXPECTED got $RET"

ADDR=$("$BUILD/vm_stowaway" resolve $T3 secret 2>/dev/null)
BP=$("$BUILD/vm_stowaway" break set $T3 $ADDR 2>&1)
echo "    $BP"
echo "$BP" | grep -q "^bp_id [0-9]" || fail "break set"
BPID=$(echo "$BP" | awk '{print $2}')
"$BUILD/vm_stowaway" break clear $T3 $BPID >/dev/null || fail "break clear"
echo "    break set+clear ok"

REGS_OUT=$("$BUILD/vm_stowaway" regions $T3 --json | head -c 80)
echo "$REGS_OUT" | grep -q '^\[{"base":"0x' || fail "regions --json"
echo "    regions --json ok"

DIFF_TARGET=$(printf 'Image+0x0' && :)  # we just need an addr; use secret
"$BUILD/vm_stowaway" diff drop --name smoke >/dev/null 2>&1 || true
"$BUILD/vm_stowaway" diff start $T3 0x100000000 0x300000000 --i32 42 --name smoke 2>&1 | sed 's/^/    /'
"$BUILD/vm_stowaway" write $T3 $ADDR "39050000" >/dev/null
sleep 1
"$BUILD/vm_stowaway" diff filter $T3 changed --name smoke 2>&1 | tail -3 | sed 's/^/    /'
"$BUILD/vm_stowaway" diff drop --name smoke >/dev/null

kill $T3 2>/dev/null
wait $T3 2>/dev/null
"$BUILD/vm_stowaway" unpatch "$PATCHED3" libvm_stowaway_payload 2>&1 | sed 's/^/    /' \
    || fail "unpatch"
otool -L "$PATCHED3" 2>/dev/null | grep -q libvm_stowaway_payload \
    && fail "unpatch: LC_LOAD_DYLIB still present"
echo "    unpatch ok"

echo "ok"
