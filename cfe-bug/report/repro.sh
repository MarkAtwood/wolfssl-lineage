#!/bin/bash
# Reproduce three cvs-fast-export defects on skeletonized masters; real CVS is the oracle.
# Usage: CFE=/path/to/cvs-fast-export CVS=/path/to/cvs ./repro.sh
set -u
CFE=${CFE:-cvs-fast-export}; CVS=${CVS:-cvs}
HERE=$(cd "$(dirname "$0")" && pwd); T=$(mktemp -d)
echo "# $($CFE --version 2>&1)  |  $($CVS --version | sed -n 2p)  |  git $(git --version | cut -d' ' -f3)"

setup() {  # setup <case>: CVS root at $T/<case>/root with module m; git repos for RCS and CVS mode
  R=$T/$1/root; mkdir -p "$R/m" && $CVS -d "$R" init && cp -a "$HERE/$1/." "$R/m/" || exit 1
  git init -q "$T/$1/rcsmode" && git init -q "$T/$1/cvsmode" || exit 1
  # RCS mode: paths relative to the module dir, no CVSROOT visible (documented `find . | cvs-fast-export`)
  (cd "$R/m" && find . -name '*,v' | sort | $CFE) 2>/dev/null | git -C "$T/$1/rcsmode" fast-import --quiet || exit 1
  # CVS mode: CVSROOT is next to the module, so cvs-fast-export detects a CVS repository
  (cd "$R" && find m -name '*,v' | sort | $CFE) 2>/dev/null | git -C "$T/$1/cvsmode" fast-import --quiet || exit 1
}
cvsfiles() { (cd "$T" && $CVS -Q -d "$R" export "$@" -d x.$$ m >/dev/null && cd x.$$ && find . -type f | sed 's#^\./##' | sort | tr '\n' ' '; mv "$T/x.$$" "$T/x.$$.$RANDOM"); }
gitfiles() { git -C "$1" ls-tree -r --name-only "$2" | grep -v '^\.gitignore$' | tr '\n' ' '; }

echo; echo "=== 1. vendor-import: start tag and trunk import"
setup vendor-import
echo "cvs export -r start      : $(cvsfiles -r start)"
echo "cfe start (RCS mode)     : $(gitfiles "$T/vendor-import/rcsmode" start)"
echo "cfe start (CVS mode)     : $(gitfiles "$T/vendor-import/cvsmode" start)"
echo "cvs export -D '2006-04-05 01:37:13 UTC': $(cvsfiles -D '2006-04-05 01:37:13 UTC')"
for mode in rcsmode cvsmode; do
  echo "cfe $mode: commits on master dated 2006-04-05 (all 1.1 revs share date, author, log):"
  git -C "$T/vendor-import/$mode" log --reverse --date=iso-strict --format='  %h %ad %s' --name-only --until=2006-04-06 master | grep -v '^$' | grep -v '\.gitignore'
done
echo "cfe rcsmode start commit vs its parent:"; git -C "$T/vendor-import/rcsmode" diff --name-status start^ start | sed 's/^/  /'

for c in branch-nosymbol branch-dead-on-parent; do
  echo; echo "=== 2. $c: sub-branch bNoMallocUpdate1 of bNoMalloc"
  setup $c
  echo "cvs export -r bNoMallocUpdate1 : $(cvsfiles -r bNoMallocUpdate1)"
  echo "cfe bNoMallocUpdate1 (RCS mode): $(gitfiles "$T/$c/rcsmode" bNoMallocUpdate1)"
  echo "cfe bNoMallocUpdate1 (CVS mode): $(gitfiles "$T/$c/cvsmode" bNoMallocUpdate1)"
done
echo; echo "# done"
