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

printf "${BOLD}${BLU}vm_stowaway smoke test${NC}\n\n"

TARGET="$BUILD/examples/target"
EXAMPLE="$BUILD/examples/controller_example"

section "Verify build outputs"
run_step "controller library" test -f "$BUILD/libvm_stowaway.a"
run_step "payload dylib"      test -f "$BUILD/libvm_stowaway_payload.dylib"
run_step "target binary"      test -x "$TARGET"

section "DYLD_INSERT_LIBRARIES backend"
OUTPUT=$("$EXAMPLE" "$TARGET" 5 2>&1 || true)
echo "$OUTPUT" | sed 's/^/    /'
echo "$OUTPUT" | grep -q "after:  secret=1337 message=rewritten from outside" || {
    echo -e "${CROSS} expected post-write values not observed"
    exit 1
}
echo
echo -e "${CHECK} ${BOLD}smoke test passed${NC}"
