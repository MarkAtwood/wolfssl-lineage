#!/bin/bash
# Compare every commit of a git trunk (newest first) against `cvs export -D <committer time>` of the module.
# Usage: trunkcheck.sh <git-dir> <rev-range> <module> <out.tsv>; prints mismatches. Ignores modes and .gitignore.
set -u; G=$1; RANGE=$2; M=$3; OUT=$4
CVS=~/GIT/cvs-local/root/usr/bin/cvs; ROOT=${CVSROOT_DIR:-~/TASKS/yassl-lineage/sourceforge/cvsroot}; W=$(mktemp -d -p ${WORK:-~/TASKS/yassl-lineage/sourceforge} exp.XXXX)
: > "$OUT"
for c in $(git -C "$G" rev-list $RANGE); do
  t=$(git -C "$G" log -1 --format=%ct $c); d=$(date -u -d @$t '+%Y-%m-%d %H:%M:%S UTC')
  rm -rf "$W/x"; (cd "$W" && $CVS -Q -d "$ROOT" export -D "$d" -d x "$M" 2>/dev/null)
  a=$(cd "$W/x" 2>/dev/null && find . -type f | sed 's#^\./##' | sort | while read f; do echo "$(git hash-object "$f") $f"; done)
  b=$(git -C "$G" ls-tree -r $c | awk '$4!=".gitignore"{print $3" "$4}' | sort -k2)
  n=$(diff <(echo "$a") <(echo "$b") | grep -c '^[<>]')
  printf "%s\t%s\t%s\t%s\n" "$c" "$d" "$n" "$(git -C "$G" log -1 --format=%s $c | cut -c1-50)" >> "$OUT"
done
rm -rf "$W"
awk -F'\t' '$3!=0' "$OUT"; echo "checked $(wc -l < "$OUT"), mismatched $(awk -F'\t' '$3!=0' "$OUT" | wc -l)"
