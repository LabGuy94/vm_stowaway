#!/usr/bin/env bash
# clone, build, install to $PREFIX. sudos the install step if needed.
set -euo pipefail

REPO="${VMSW_REPO:-https://github.com/LabGuy94/vm_stowaway.git}"
REF="${VMSW_REF:-master}"
PREFIX="${PREFIX:-/usr/local}"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    cat <<EOF
usage: install.sh [--prefix PATH]

env:
  PREFIX     install root (default /usr/local)
  VMSW_REPO  git url (default https://github.com/LabGuy94/vm_stowaway.git)
  VMSW_REF   branch / tag / sha to check out (default master)
EOF
    exit 0
fi
if [[ "${1:-}" == "--prefix" && -n "${2:-}" ]]; then PREFIX="$2"; fi

for cmd in git make cc codesign; do
    command -v "$cmd" >/dev/null || {
        echo "missing $cmd: install Xcode command-line tools (xcode-select --install)"
        exit 1
    }
done

SRC="$(mktemp -d -t vm_stowaway.XXXXXX)"
trap 'rm -rf "$SRC"' EXIT

echo "==> cloning $REPO@$REF"
git clone --depth 1 --branch "$REF" "$REPO" "$SRC" >/dev/null

echo "==> building"
make -C "$SRC" -j"$(sysctl -n hw.ncpu)" >/dev/null

echo "==> installing to $PREFIX"
if [[ -w "$PREFIX" || ( -w "$(dirname "$PREFIX")" && ! -e "$PREFIX" ) ]]; then
    make -C "$SRC" install PREFIX="$PREFIX" >/dev/null
else
    sudo make -C "$SRC" install PREFIX="$PREFIX" >/dev/null
fi

echo
echo "vm_stowaway installed:"
command -v vm_stowaway || echo "  $PREFIX/bin/vm_stowaway"
