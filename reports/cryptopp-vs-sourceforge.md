# Crypto++ git history vs SourceForge originals (2026-10-02)

Verdict: the git history behind `cryptopp-5.1` (b2f710a95522...) is a faithful
conversion of SourceForge SVN `trunk/c5` r2..r49. All 48 commit trees match the
original SVN and CVS exactly. Git lacks the `c50-fixes` branch, the `WEIDAI`
vendor branch, the `c50-fixes-merged` tag, and all Crypto++ history before 5.0.

## Sources

- CVS: https://sourceforge.net/code-snapshots/cvs/c/cr/cryptopp.zip, saved as
  `cryptopp-cvs.zip` (3,342,544 B), sha256
  `55c4d3a26695be533d1d5797334319f811d1e3d889d0bc85f549558740b4d6b2`.
  Modules: `c5`, `src`, `test`, `CVSROOT`.
- SVN: `svnrdump dump` of https://svn.code.sf.net/p/cryptopp/code r0..r610,
  saved as `cryptopp-svn-r0-610.dump` (13,533,215 B), sha256
  `eafdd69511de95cd09df13c24b4d0077540da8a44f451d1b812bc537e0255941`. No SVN
  snapshot zip exists (404).
- svn 1.14.3 unpacked with `dpkg -x` into `~/GIT/svn-local` (not installed).

## Method

- Git commit k corresponds to SVN r(k+1); r1 only creates the top-level dirs.
- SVN: each revision exported (`--ignore-keywords --native-eol LF`), hashed as
  a git tree (paths, contents, modes), compared with the git commit's tree.
- CVS: `cvs export -ko -D "<commit UTC time>" c5` per commit, same comparison.
- Missing refs: each CVS tag/branch export compared with the SVN path/revision.
- Metadata: SVN author, date and log vs git.

## Results

- SVN: 48/48 git trees equal SVN `trunk/c5` at the same revision.
- CVS: 48/48 consistent. 46 match at the exact timestamp; r2 and r3 are the
  initial import (17:31:41 to 17:32:03, stamped with the first second by
  cvs2svn) and equal the CVS state at 17:32:03.
- Metadata: 48/48 identical.
- CVS vs SVN on refs git lacks: all match (`CRYPTOPP_5_0`, `CRYPTOPP_5_1` tree
  c9e740b3, `WEIDAI`, `c50-fixes-merged`, `c50-fixes` at r23, r25, r29, r34,
  r36 and head). SVN r22 is indistinguishable in CVS from r23 (same second).

## Original refs at or before 5.1 that git lacks

- `c5` module: vendor branch `WEIDAI` (equals the 5.0 import); branch
  `c50-fixes` (2002-12-06 to 2003-03-10), whose 5 content commits (r23, r25,
  r29, r34, r36) appear in git only as empty commits keeping the messages; tag
  `c50-fixes-merged`.
- `src` module (CVS only; never in SVN): about 100 changesets, 2000-06-26
  (import of Crypto++ 3.2) to 2002-12-12, listed in `src_changesets.txt`. Tags
  `CRYPTOPP_3_2`, `CRYPTOPP_4_0`, `CRYPTOPP_4_1`, `CRYPTOPP_4_2`, vendor tag
  `start`, vendor branch `WEIDAI`. Release-tag exports in `srcrefs/`.
- `CRYPTOPP_4_1_RC1`: in `CVSROOT/val-tags` and `history` (2001-01-10) but on no
  file any more; deleted, not recoverable.
- `test` module (2003-07, after 5.1): out of scope.

## Odd things

1. Git is one chain through every SVN revision. The 11 commits that touched
   only branches or tags (r3, r4, r5, r22, r23, r25, r29, r34, r36, r37, r49)
   are empty; some carry messages (e.g. "port to Darwin/gcc 3.x") whose changes
   are not in that commit's tree.
2. Tag dates are synthetic: `CRYPTOPP_5_1` was created 2003-04-19 by date
   (`rtag -D 2003.03.23.05.00.00`); the 2003-03-22 git date is cvs2svn's.
   `c50-fixes-merged` was first tagged 2002-12-06 but holds 2003-03-10 changes,
   so it was moved later.

## Files

`cvsroot/`, `svnrepo/`, `exports/`, `cvsexports/`, `cvsrefs/`, `srcrefs/`,
`compare_svn.sh`, `compare_cvs.sh`, `compare_refs.sh`, `symnames.py`,
`rcscommits.py`, `compare_svn.out`, `compare_cvs_ko.out`, `compare_refs.out`,
`compare_meta.out`, `src_changesets.txt`, `svnlog-*`, `scratch.git`.
