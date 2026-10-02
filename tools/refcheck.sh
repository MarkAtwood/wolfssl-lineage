#!/bin/bash
# For every commit on every ref of a built repo, compare tree (path, mode, blob) with cvs export.
# Ref tips: -r REF. Commits on trunk: -D time. Commits only on a branch: -r BRANCH -D time. Tags: -r TAG.
set -u; G=$1; M=$2; CVS=~/GIT/cvs-local/root/usr/bin/cvs; ROOT=${CVSROOT_DIR:-~/TASKS/yassl-lineage/sourceforge/cvsroot}
W=$(mktemp -d -p ${WORK:-~/TASKS/yassl-lineage/sourceforge} chk.XXXX); bad=0; n=0
exp(){ rm -rf "$W/x"; (cd "$W" && $CVS -Q -d "$ROOT" export "$@" -d x "$M" 2>/dev/null); (cd "$W/x" 2>/dev/null && find . -type f | sed 's#^\./##' | sort | while read f; do m=100644; [ -x "$f" ] && m=100755; echo "$m $(git hash-object "$f") $f"; done); }
gt(){ git -C "$G" ls-tree -r "$1" | awk '{print $1" "$3" "$4}' | sort -k3; }
chk(){ n=$((n+1)); d=$(diff <(exp "${@:2}") <(gt "$1") | grep -c '^[<>]'); [ "$d" != 0 ] && { bad=$((bad+1)); echo "MISMATCH $d $(git -C "$G" log -1 --format='%h %ad %s' --date=short "$1" | cut -c1-60) [${*:2}]"; }; }
for t in $(git -C "$G" tag); do chk "$t^{commit}" -r "$t"; done
for b in $(git -C "$G" branch --format='%(refname:short)'); do [ $b = master ] && chk master -r HEAD || chk "$b" -r "$b"; done
for c in $(git -C "$G" rev-list master); do chk $c -D "$(date -u -d @$(git -C "$G" log -1 --format=%ct $c) '+%Y-%m-%d %H:%M:%S UTC')"; done
for b in $(git -C "$G" branch --format='%(refname:short)' | grep -v -E '^(master|touska|Alexey)$'); do
  for c in $(git -C "$G" rev-list $b ^master); do chk $c -r $b -D "$(date -u -d @$(git -C "$G" log -1 --format=%ct $c) '+%Y-%m-%d %H:%M:%S UTC')"; done; done
rm -rf "$W"; echo "$M: checked $n, mismatched $bad"
