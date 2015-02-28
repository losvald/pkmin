#!/bin/sh
[ $# -lt 1 ] && echo "Usage: $0 KEY" >&2 && exit 1
k="$1"
shift 1

[ -z "$GPG" ] && GPG=gpg
[ -z "$PYTHON" ] && PYTHON=python
ram="/run/shm"
min="$ram/$k.min"
pub="$ram/$k.pub"
sec="$ram/$k.sec"
rec="$ram/$k.rec"
set -o xtrace
trap "shred -u '$rec' '$sec' '$pub'" EXIT
$GPG --export "$k" > "/run/shm/$k.pub"
[ ! -s "$pub" ] && echo "Failed to extract pub key" >&2 && exit 1
$GPG --export-secret-keys "$k" > "$sec"
[ ! -s "$sec" ] && echo "Failed to extract sec key" >&2 && exit 2
script_dir=$(dirname "$(readlink -f "$0")")
$PYTHON "$script_dir/../pkmin.py" "$k" "$@" > "$min"
$PYTHON "$script_dir/../pkmin.py" -r "$min" --pubring "$pub" "$k" "$@" > "$rec"
echo -e "REMINDER: after inspecting it, shred the minified key: $rec">/dev/null
diff -sq "$sec" "$rec"
