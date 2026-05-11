#!/usr/bin/env python3
"""launch a target, read its globals, rewrite them. mirrors examples/controller_example.c"""

import sys
import vm_stowaway as vms


def main(target: str) -> int:
    with vms.launch(target, ["10"]) as h:
        print(f"launched pid {h.pid}, payload v{h.remote_info()[0]}")

        secret  = h.resolve("secret")
        message = h.resolve("message")
        print(f"secret @ 0x{secret:x}, message @ 0x{message:x}")

        print(f"before: secret={h.read_u32(secret)} message={h.read(message, 32).split(b'\\0', 1)[0].decode()}")

        h.write_u32(secret, 1337)
        h.write(message, b"rewritten from python\0")

        print(f"after:  secret={h.read_u32(secret)} message={h.read(message, 32).split(b'\\0', 1)[0].decode()}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: launch.py <target-path>", file=sys.stderr)
        sys.exit(1)
    sys.exit(main(sys.argv[1]))
