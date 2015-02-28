#!/bin/sh
[ $# -lt 1 ] && echo "Usage: $0 WIDTH" >&2 && exit 1
w="$1"
fold -w$w | while read -r ln; do
    printf "%-*s %08X\n" $w "$ln" "$(echo -n "$ln" | cksum | cut -d' ' -f1)"
done
