#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

BUILD="${1:-build}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YEL='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
CHECK="${GREEN}✔${NC}"; CROSS="${RED}✖${NC}"
INFO="${CYN}➜${NC}"; WARN="${YEL}⚠${NC}"

section() { echo; printf "${BOLD}${CYN}==> %s${NC}\n" "$1"; }

run_step() {
    local msg="$1"; shift
    printf "${CYN}[..]${NC} %s\r" "$msg"
    if "$@" >/tmp/vmsw-step.log 2>&1; then
        printf "\r\033[K${CHECK} %s\n" "$msg"
    else
        printf "\r\033[K${CROSS} %s\n" "$msg"
        echo "    output:"; sed 's/^/    /' /tmp/vmsw-step.log
        exit 1
    fi
}

banner() {
    printf "${BOLD}${BLU}"
    cat <<'EOF'
                                                _
__   ___ __ ___    ___| |_ _____      ____ ___ _   _
\ \ / / '_ ` _ \  / __| __/ _ \ \ /\ / / _` |\ \ / /
 \ V /| | | | | | \__ \ || (_) \ V  V / (_| | \ V /
  \_/ |_| |_| |_| |___/\__\___/ \_/\_/ \__,_|  \_/
EOF
    printf "${NC}\n"
    echo -e "${CYN}smoke test (DYLD_INSERT_LIBRARIES path)${NC}\n"
}

banner

TARGET="$BUILD/examples/target"
EXAMPLE="$BUILD/examples/controller_example"

if [[ ! -x "$TARGET" || ! -x "$EXAMPLE" ]]; then
    echo -e "$CROSS missing build outputs; run \`make\` first"
    exit 1
fi

section "Verify build outputs"
run_step "controller library" test -f "$BUILD/libvm_stowaway.a"
run_step "payload dylib"      test -f "$BUILD/libvm_stowaway_payload.dylib"
run_step "mach shim dylib"    test -f "$BUILD/libvm_stowaway_machshim.dylib"
run_step "vm_stowaway CLI"    test -x "$BUILD/vm_stowaway"
run_step "target binary"      test -x "$TARGET"
run_step "mach_client binary" test -x "$BUILD/examples/mach_client"

section "DYLD_INSERT_LIBRARIES backend"
OUTPUT=$("$EXAMPLE" "$TARGET" 5 2>&1 || true)
echo "$OUTPUT" | sed 's/^/    /'
echo "$OUTPUT" | grep -q "after:  secret=1337 message=rewritten from outside" || {
    echo -e "${CROSS} DYLD path: expected post-write values not observed"
    exit 1
}
echo -e "${CHECK} DYLD_INSERT_LIBRARIES backend ok"

section "LC_LOAD_DYLIB patcher backend"
PATCHED=$(mktemp -t vmsw-target.XXXXXX)
cp "$TARGET" "$PATCHED"
chmod +x "$PATCHED"   # mktemp creates 0600; restore exec bit
"$BUILD/vm_stowaway" patch "$PATCHED" "$PWD/$BUILD/libvm_stowaway_payload.dylib" \
    2>&1 | sed 's/^/    /'

"$PATCHED" 15 > "$PATCHED.out" 2>&1 &
TPID=$!
disown 2>/dev/null || true
trap '{ kill $TPID 2>/dev/null; wait $TPID 2>/dev/null; rm -f "$PATCHED" "$PATCHED.out"; } >/dev/null 2>&1' EXIT
sleep 1

ADDR=$("$BUILD/vm_stowaway" resolve $TPID secret 2>/dev/null)
[[ -n "$ADDR" ]] || { echo -e "${CROSS} resolve failed"; exit 1; }
echo "    secret at $ADDR"
"$BUILD/vm_stowaway" write $TPID $ADDR "39050000" | sed 's/^/    /'
sleep 2
if grep -q "secret=1337" "$PATCHED.out"; then
    echo -e "${CHECK} LC_LOAD_DYLIB backend ok"
else
    echo -e "${CROSS} patcher path: target never observed new value"
    sed 's/^/    /' < "$PATCHED.out"
    exit 1
fi

section "mach API shim (DYLD_INTERPOSE over mach_vm_*)"
PATCHED2=$(mktemp -t vmsw-shimtest.XXXXXX)
cp "$TARGET" "$PATCHED2"
chmod +x "$PATCHED2"
"$BUILD/vm_stowaway" patch "$PATCHED2" "$PWD/$BUILD/libvm_stowaway_payload.dylib" \
    >/dev/null 2>&1
"$PATCHED2" 20 > "$PATCHED2.out" 2>&1 &
T2=$!
disown 2>/dev/null || true
trap '{ kill $T2 2>/dev/null; wait $T2 2>/dev/null; rm -f "$PATCHED2" "$PATCHED2.out"; } >/dev/null 2>&1' EXIT
sleep 1

SECRET=$("$BUILD/vm_stowaway" resolve $T2 secret 2>/dev/null)
echo "    secret @ $SECRET"
echo "    running mach_client through shim ..."
OUT=$("$BUILD/vm_stowaway" wrap --pid $T2 -- \
    "$BUILD/examples/mach_client" $T2 $SECRET 4 "39050000" 2>&1)
echo "$OUT" | sed 's/^/    /'
sleep 2

fail=0
grep -q "secret=1337" "$PATCHED2.out" || { echo "    target never observed write"; fail=1; }
echo "$OUT" | grep -q "wrote 4 bytes"             || { echo "    no write ack";        fail=1; }
echo "$OUT" | grep -q "^region:"                  || { echo "    no region walked";    fail=1; }
echo "$OUT" | grep -q "dyld_all_image_infos @ 0x" || { echo "    no TASK_DYLD_INFO";   fail=1; }
echo "$OUT" | grep -q "task_basic_info: vsz="     || { echo "    no TASK_BASIC_INFO";  fail=1; }
echo "$OUT" | grep -q "^task_threads: "           || { echo "    no task_threads";     fail=1; }
echo "$OUT" | grep -q " pc=0x"                    || { echo "    no thread_get_state"; fail=1; }
echo "$OUT" | grep -q 'alloc/rt:.*round-trip'     || { echo "    no alloc round-trip"; fail=1; }
echo "$OUT" | grep -q "^pid_for_task: "           || { echo "    no pid_for_task";    fail=1; }
echo "$OUT" | grep -q "^vm_read_overwrite: "      || { echo "    no legacy vm_read";  fail=1; }
echo "$OUT" | grep -q "^thread_info: ok"          || { echo "    no thread_info";     fail=1; }
if [[ $fail -eq 0 ]]; then
    echo -e "${CHECK} mach API shim ok"
else
    echo -e "${CROSS} mach API shim path failed"
    exit 1
fi

echo
echo -e "${CHECK} ${BOLD}smoke test passed${NC}"
