from __future__ import print_function

import sys
import binascii

OCTETS_PER_LINE = 16            # use the same count as most hex editors
INDENT_SPACES = 4

if __name__ == '__main__':
    if sys.argv[1:]:
        print(sys.argv[1], "= ", end="")
    print("(")
    octets = sys.stdin.read()
    for i in range(0, len(octets), OCTETS_PER_LINE):
        print(" " * INDENT_SPACES, 'b"', sep="", end="")
        for octet in octets[i : i + OCTETS_PER_LINE]:
            print(r"\x%02X" % ord(octet), sep="", end="")
        print('"')
    print(")")
