#!/bin/sh
gpg --fingerprint --fingerprint "$@" \
    | grep 'fingerprint' \
    | sed -e 's/Key fingerprint =//' -e 's/\([0-9A-F]\{2\}\)/\\x\1/g' \
    -e 's/ \([0-9A-Fx\\]*\)\b/b"\1" /g' -e 's/^ \+//' \
    | sed "s/^\(\( *[^ ]*\)\{10\}\)/(\1),/" \
    | sed "s/^\(\( *[^ ]*\)\{5\}\)/\1\n/"
