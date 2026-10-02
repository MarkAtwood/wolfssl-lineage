<!-- DRAFT. Not filed. Target: https://gitlab.com/esr/cvs-fast-export/-/issues (attach cfe-bug-yassl.tar.gz). Could be split into three issues. -->

# 2.5: vendor import drops files from `start` and splits into N commits; sub-branch keeps files it never had

cvs-fast-export 2.5 gets three things wrong on a plain single `cvs import` repository, measured against `cvs export` from CVS 1.12.13:

1. **The vendor-branch commit deletes every file still on default branch 1.1.1.** The tag `start` lacks 21 of 126 files (cyassl) and 24 of 203 (yassl). RCS mode only.
2. **One `cvs import` becomes N trunk commits.** 126 `1.1` revisions with the same author and log, spread over 49 s, come out as 22 commits (yassl: 203 revisions over 10 s, 25 commits). The import is cut at each default-branch file.
3. **A sub-branch inherits files that have no symbol for it.** `bNoMallocUpdate1`, a branch off branch `bNoMalloc`, plus its tags `noMalloc-CheckIn` and `noMallocUpdate1-IOadd`, has 166 files where CVS has 151.

Each one reproduces with 2 or 3 skeletonized masters. The tarball holds the masters, `repro.sh`, and a transcript.

## Environment

- cvs-fast-export 2.5, built from gitlab.com/esr/cvs-fast-export commit 0043737 ("Ready to ship 2.5")
- Oracle: CVS 1.12.13-MirDebian-30, `cvs -Q -d <root> export -r <tag>` and `-D <date>`
- git 2.55.0, Linux x86_64
- Source data: public SourceForge CVS snapshot of yaSSL/CyaSSL, https://sourceforge.net/code-snapshots/cvs/y/ya/yassl.zip (sha256 `61f1d24167a1c5c00fd799cd4170029dfd554cb6602ac43863a7fd32cd7bd10d`), modules `cyassl` (274 masters) and `yassl` (297 masters)
- Invocation: `cd <module> && find . -name '*,v' | sort | cvs-fast-export | git fast-import`, the documented `find . | cvs-fast-export` form. No CVSROOT is visible from there, so `detectCVSRoot` returns false and the run is in RCS mode. "CVS mode" below means the same masters run from the root as `find m -name '*,v'`, so that `./CVSROOT` is seen.

## Reproducer

`cfe-bug-yassl.tar.gz` (8 KB):

| dir | masters | shows | stripped with |
|---|---|---|---|
| `vendor-import/` | 3 | bugs 1 and 2 | `cvsstrip -t -c` (see note) |
| `branch-nosymbol/` | 2 | bug 3, file lacks sub-branch symbol | `cvsstrip -t` |
| `branch-dead-on-parent/` | 2 (one in Attic) | bug 3, file dead on parent branch | `cvsstrip -t` |

Paths were flattened (`dir/x` became `dir__x`). Each set is a ddmin reduction of the full module, and I re-checked every set against `cvs export` on a CVS root built from those files alone.

Note on `vendor-import`: plain `cvsstrip` gives `1.1` and `1.1.1.1` different content. In the real data they are byte-identical (all 126 cyassl and 203 yassl `1.1.1.1` deltas are empty), so stripping changes how bug 2 shows up. `-c` keeps the original content (GPL source, a few KB) and still hashes the logs. With full stripping, bug 1 still reproduces; bug 2 is covered under "Mechanism" below.

Run: `CFE=/path/to/cvs-fast-export CVS=/path/to/cvs ./repro.sh`. Transcript excerpt (logs are cvsstrip hashes):

```
=== 1. vendor-import: start tag and trunk import
cvs export -r start      : testsuite__input testsuite__Makefile.am testsuite__quit
cfe start (RCS mode)     : testsuite__Makefile.am
cfe start (CVS mode)     : testsuite__Makefile.am testsuite__input testsuite__quit
cvs export -D '2006-04-05 01:37:13 UTC': testsuite__input testsuite__Makefile.am testsuite__quit
cfe rcsmode: commits on master dated 2006-04-05 (all 1.1 revs share date, author, log):
  4049f2e 2006-04-05T01:37:13Z da28248b4ec75efbe0ba7461142ed60d
testsuite__Makefile.am
testsuite__input
  6d40ec5 2006-04-05T01:37:13Z da28248b4ec75efbe0ba7461142ed60d
testsuite__quit
cfe rcsmode start commit vs its parent:
  D	testsuite__input
  D	testsuite__quit

=== 2. branch-nosymbol: sub-branch bNoMallocUpdate1 of bNoMalloc
cvs export -r bNoMallocUpdate1 : include__cyassl_int.h
cfe bNoMallocUpdate1 (RCS mode): cyassl.xcodeproj__project.pbxproj include__cyassl_int.h
cfe bNoMallocUpdate1 (CVS mode): cyassl.xcodeproj__project.pbxproj include__cyassl_int.h

=== 2. branch-dead-on-parent: sub-branch bNoMallocUpdate1 of bNoMalloc
cvs export -r bNoMallocUpdate1 : include__cyassl_int.h
cfe bNoMallocUpdate1 (RCS mode): aclocal.m4 include__cyassl_int.h
cfe bNoMallocUpdate1 (CVS mode): aclocal.m4 include__cyassl_int.h
```

## Bug 1: vendor-branch commit deletes default-branch files (RCS mode)

**Input.** One `cvs import`. Every file has `1.1` "Initial revision" and `1.1.1.1` "cyassl 0.5.1 cvs import", with identical dates and identical content. Files later committed on trunk have `1.2+` and no `branch` header. Files never touched again keep `branch 1.1.1;` (21 in cyassl, 24 in yassl). `start` is `1.1.1.1` in every file.

**Actual (RCS mode).** The commit on `import-1.1.1` carries `D` for every file that has `branch 1.1.1;`, and `start` points at it. cyassl `start` has 105 files; `cvs export -r start` has 126. The 21 missing files are exactly the 21 masters with `branch 1.1.1;` (AUTHORS, COPYING, ChangeLog, NEWS, certs/dh1024.der, ...). yassl: 179 vs 203.

**Actual (CVS mode).** Correct. `start` has all 126 / 203 files, and a `touska` branch (the vendor symbol) is emitted next to `import-1.1.1`. The same masters give different `start` trees depending on whether a CVSROOT directory happens to be visible.

**Expected.** `start` equals `cvs export -r start` in both modes. The vendor commit has no `D` ops: the default-branch files have `1.1.1.1` and are not dead.

**Known?** This is the second symptom in #57 (closed 2023-12-28): "commit a01ad40 in the import-1.1.1 branch removes parapin-1.0.0.ebuild but it shouldn't." At 0043737, `tests/issue-57.chk` line 66 still expects `D parapin-1.0.0.ebuild` in the `import-1.1.1` commit, so the regression test locks in the reported behavior.

## Bug 2: single import split at each default-branch file (both modes)

**Input.** The same import. All `1.1` revisions have the same author (`touska`) and the same log. The time span is 49 s (cyassl) or 10 s (yassl), well inside the default 300 s window. No commitids.

**Actual.** cyassl: 22 trunk commits for 126 `1.1` revisions. yassl: 25 for 203. Each commit ends at a file with `branch 1.1.1;` (21 and 24 such files, giving 22 and 25 runs). The commits are cumulative prefixes of the import, not time slices. The commit dated 01:36:39 has 3 files, including two dated 01:36:24, while CVS has 9 files at 01:36:39. Of the 22 cyassl commits, 19 match no `cvs export -D` state; the 3 that do are the last commits of a same-timestamp group. In the 3-file reproducer all `1.1` revisions share one timestamp (01:37:13) and still produce 2 commits.

**Expected.** One trunk commit holding all `1.1` revisions, per the man page's coalescing rule (same author, same log, within the fuzz window).

**Mechanism (observed, not traced in code).** With content-stripped masters (`cvsstrip -t -l`, so `1.1` != `1.1.1.1`), master becomes:

```
e2b0d16 *** empty log message ***   A Makefile.am  A input   (1.1)
d1697da cyassl 0.5.1 cvs import     M input                 (1.1.1.1)
6c25acc *** empty log message ***   A quit                  (1.1)
f05bb02 cyassl 0.5.1 cvs import     M quit                  (1.1.1.1)
```

The vendor head is spliced onto trunk for each file that has no `1.2` (`PatchVendorBranches`). Each file's `1.1.1.1` then sits between `1.1` cliques at the same timestamp and cuts them. With real data the `1.1.1.1` commits change nothing and disappear, but the cuts remain.

## Bug 3: sub-branch tree keeps parent-branch files that lack its symbol (both modes)

**Input.** `bNoMalloc` branches from trunk. `bNoMallocUpdate1` branches from `bNoMalloc`. Two kinds of file have no `bNoMallocUpdate1` symbol:

- `cyassl.xcodeproj/project.pbxproj`: on `bNoMalloc` (`1.2.0.2`) but never tagged for the sub-branch.
- `aclocal.m4` and 13 other autotools files: killed on `bNoMalloc` in one commit (state dead, 2008-10-21 22:19:55), before the sub-branch was created. `include/cyassl_int.h` roots the sub-branch at `1.26.2.1` (2008-10-21 21:39:11). Its next `bNoMalloc` revision, `1.26.2.2`, is dated 2008-10-22 23:42:38.

**Actual.** cfe forks `bNoMallocUpdate1` from the `bNoMalloc` commit for `1.26.2.1` and keeps that commit's whole tree. Files with no `bNoMallocUpdate1` symbol stay in. In the 2-file reproducers, `cvs export -r bNoMallocUpdate1` has 1 file and cfe has 2. In the full cyassl module, cfe emits "Synthetic branch base for mixed CVS branch state" with parent 32b39f7 (the first `bNoMalloc` commit, 21:39:11, before the 22:19:55 removal). That commit changes only `configure`, so the branch and both tags carry 15 files CVS does not: `aclocal.m4`, `Makefile.in`, 11 more `*/Makefile.in`, `ctaocrypt/include/config.h`, `cyassl.xcodeproj/project.pbxproj`. The counts are 166 vs 151 for `bNoMallocUpdate1` and `noMallocUpdate1-IOadd`, and 165 vs 150 for `noMalloc-CheckIn`.

**Expected.** A file with no symbol for a branch or tag is absent from it, as `cvs export -r` shows. The branch base should delete such files rather than inherit them.

## Checked and not a bug

- yassl `certs/ca-cert.pem` in "add multi CA cert support in one file" (2006-07-12 20:54:55) differs from `cvs export -D` by one line. The file embeds curl's literal `$Id: ca-bundle.crt,v 1.2 2003/03/24 ... $`, which CVS expands and cfe, as documented, does not. The blob equals `cvs co -ko -r1.2`, and `-R` maps `certs/ca-cert.pem 1.2` to that commit.
- "Initial revision" becoming "*** empty log message ***" is `normalizeLog`, which is intended.
- Not tried: the documented workaround (a final trunk commit to every file).

## Addendum: trunk ignores later vendor imports (found after this draft)

Input: SourceForge Crypto++ CVS (https://sourceforge.net/code-snapshots/cvs/c/cr/cryptopp.zip), module `src`, three `cvs import`s onto vendor branch `WEIDAI` (1.1.1.1, 1.1.1.2, 1.1.1.3). Example `arc4.h`: 1.1 and 1.1.1.1 (2000-06-26 05:32:54), 1.1.1.2 (2000-06-26 06:12:02), first trunk commit 1.2 on 2001-01-10. At 2001-01-05 `cvs export -D` gives 1.1.1.2 (CVS follows the vendor branch while the only trunk revision is the import); cvs-fast-export's trunk has 1.1. Consequence: release tags `CRYPTOPP_4_1` and `CRYPTOPP_4_2` (exact per-file revisions) appear as states on CVS's trunk but on no cvs-fast-export trunk commit; 37 of 43 post-import changesets differ. Not yet reduced to a minimal repro.
