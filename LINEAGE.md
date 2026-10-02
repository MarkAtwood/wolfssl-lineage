# wolfssl-lineage

Reconstructed history of yaSSL (C++, 2004-2017), CyaSSL (C, 2006-2011) and
its continuation wolfSSL (git from 2011-02-05), plus the upstream bignum
libraries they were built on (Crypto++, LibTomMath, TomsFastMath). Local
reconstruction; not an official wolfSSL repository. `git log main` runs from
the Crypto++ 3.2 import (2000-06-26) to wolfSSL master.

## Branches and refs

- `yassl`: yaSSL 0.0.2 and 0.0.3 as source-only commits (see "yaSSL 0.0.2 and
  0.0.3"), releases 0.2.0..1.2.2 as snapshots, then the yaSSL CVS history
  (201 commits, 2006-03-28 "yaSSL 1.2.2 cvs import" .. 2015-03-18), then
  releases 2.3.7c..2.4.4 as snapshots. 241 commits on the branch line from
  yaSSL 0.0.2.
- `cyassl`: CyaSSL releases 0.2.0..0.5.0 as snapshots, then the CyaSSL CVS
  history (200 commits, 2006-04-05 "cyassl 0.5.1 cvs import" .. 2011-01-06).
  204 commits on the branch line from CyaSSL 0.2.0.
- `main`: wolfSSL `master` (upstream `0bcda7efa2ec`) with the grafts below
  baked in. Its tree equals upstream's, but every yaSSL, CyaSSL and wolfSSL
  commit ID is rewritten, so `main` commit IDs do NOT match upstream wolfSSL.
  Translate with `commit-map.txt` on this branch (old ID, new ID per line; a
  copy of the builder's `.git/filter-repo/commit-map` after the last bake).
  filter-repo chained all six bakes, so its keys are the original IDs
  (upstream wolfSSL, and the first snapshot/CVS build) and its values are the
  current IDs; e.g. wolfSSL "1.8.8 init" `6b88eb05b` is `57735b92db94` here.
- `notes`: this file plus `catalog.tsv`, on an orphan branch.
- `cvs/yassl/*`, `cvs/cyassl/*` (branches and tags): every CVS tag and branch
  from the SourceForge repository; see "CVS history".
- `cvs/cryptopp-src/*`, `cvs/cryptopp-c5/*`: Crypto++ CVS refs; see "Crypto++
  CVS history". `cvs/cryptopp-src/trunk` is the Crypto++ 3.x/4.x line, which
  continues two commits past the 5.0 fork (to 2002-12-12).
- Graft 1 (permanent): wolfSSL's root commit "1.8.8 init" (2011-02-05,
  `57735b92db94`) is a child of the `cyassl` tip, the last CyaSSL CVS commit
  (2011-01-06, `6124bc1f4cf8`; originally `adc5a5503`).
- Tags `yassl-<ver>`, `cyassl-<ver>`: annotated. Release tags whose `Kind:` is
  `snapshot` have tree == release archive (byte-identical, verified). Releases
  dated inside a CVS window are side commits: the exact archive tree, parented
  on the last CVS commit at or before the release date, so the branch line
  stays pure CVS and each release shows where it forked. Releases before or
  after the CVS window are on the branch line. `wolfssl-tag` tags sit on
  wolfSSL commits carrying the matching wolfSSL `v<ver>` tag.
- Graft 2 (permanent, interpretive): CyaSSL 0.2.0 (2006-02-19, `7b23622e94d7`;
  originally `85faa773e`) is a child of yaSSL 1.1.5 (2006-01-09,
  `7cfc8f7f9402`, originally `4dcebc25b`, the yaSSL release current at the
  time). `git merge-base yassl main` is yaSSL 1.1.5.
  This records lineage, not code flow; see "yaSSL and CyaSSL" below.
- Graft 3 (permanent): upstream bignum libraries as extra merge parents on
  the commits that imported them, plus LibTomCrypt (ECC) the same way; see
  "Upstream library ancestry" below.
  `git log --first-parent main` stays on the yaSSL/CyaSSL/wolfSSL line.
- Graft 4 (permanent, interpretive): the Crypto++ 5.0 import (root of the
  upstream git history, "Initial revision" 2002-10-04 17:31:41, `2b81d01420d8`)
  is a child of the Crypto++ 4.x CVS trunk commit current at that moment
  ("fix for MacOS X", 2002-10-04 00:38:40, `9322c7ddd427`). Wei Dai imported
  5.0 as a fresh CVS module (`c5`) rather than continuing `src`, so no commit
  records the link; this records lineage, like graft 2.
- Tags `cryptopp-5.1`, `libtommath-0.38`, `tomsfastmath-0.10`,
  `libtomcrypt-1.17`: the upstream annotated tags (`CRYPTOPP_5_1`, `0.38`,
  `0.10`, `1.17`), renamed. Since graft 4 the Crypto++ commits have new IDs
  (`cryptopp-5.1` is `67c42df98eba` here, upstream `b2f710a95`); the LibTom
  commits keep upstream IDs.
- All grafts were baked in on 2026-10-02 in six bakes: grafts 1-2, the
  bignum part of graft 3, LibTomCrypt, the CVS layer rebuild, the Crypto++
  CVS history (graft 4), and yaSSL 0.0.2/0.0.3. Each was
  first a replace ref, then baked with
  `git filter-repo --proceed --force --replace-refs delete-no-add` (bakes 2-6
  also `--prune-empty never --prune-degenerate never`). No replace refs
  remain; a plain clone shows the full history. LibTom commits and `notes`
  keep their IDs.
- Pre-bake backups: a mirror was taken before each bake; all were deleted on
  2026-10-02 after the final push, and with them the `refs/pre-cvs/*`
  snapshot-only fallback refs, the Software Heritage-derived CVS layer, and
  the intermediate commit IDs. `commit-map.txt` still maps original IDs to
  current ones.

## CVS history

Source: SourceForge's raw CVS repository snapshot
<https://sourceforge.net/code-snapshots/cvs/y/ya/yassl.zip> (5,544,041 bytes,
sha256 `61f1d24167a1c5c00fd799cd4170029dfd554cb6602ac43863a7fd32cd7bd10d`),
the RCS `,v` masters for modules `yassl` (297 files, 1,860 revisions) and
`cyassl` (274 files, 1,904 revisions). Oracle: real CVS 1.12.13 run on that
repository (`cvs export`, `cvs co -p -r REV`).

Build (`tools/build_cvs.py`):

- Changeset grouping and commit metadata come from cvs-fast-export 2.5
  (`-A authors.map -R revmap`). File contents do not: every file revision is
  checked out with `cvs co -p -r REV` (default keyword expansion, as in
  `cvs export` and the release tarballs), deletions are accepted only where
  RCS has a dead revision within cvs-fast-export's 300 s window, and file
  modes come from the `,v` masters' execute bits.
- The trunk 1.1 revisions of the initial `cvs import`, which cvs-fast-export
  splits into 25 (yassl) / 22 (cyassl) "empty log message" commits, are one
  commit carrying the vendor revision's message and time ("yaSSL 1.2.2 cvs
  import", "cyassl 0.5.1 cvs import"); its tree equals `cvs export -r start`.
- Every cvs-fast-export synthetic commit (branch bases, mixed-state tags)
  takes its tree from `cvs export -r SYMBOL`.
- Authors: `touska` = Todd Ouska <todd@yassl.com>, `chrisconlon` = Chris
  Conlon <chris@wolfssl.com>, `myassl` and `uid182869` = `<name>@users.sourceforge.net`.

Verification, all against `cvs export` and including file modes: every trunk
commit at its timestamp (yassl 201/201, cyassl 200/200, re-run after the
bake), every branch commit on its branch, and every tag and branch tip
(17/17). Unused RCS dead revisions: 3, all "file was initially added on
branch" placeholders.

CVS refs (`refs/heads/cvs/<module>/*`, `refs/tags/cvs/<module>/*`):

- yassl: vendor branch `touska` and tag `start` (both the import commit).
- cyassl: branches `bNoMalloc` (2008-10/12, 10 commits), `bNoMallocUpdate1`
  (2008-10, sub-branch of bNoMalloc), `dtls-branch` (2009-04, 3 commits),
  `Alexey` (branch point only, no commits), vendor branch `touska`; tags
  `start`, `v0-9-9e`, `noMalloc-CheckIn`, `noMalloc-Merge-IO`,
  `noMallocUpdate1-IOadd`, `bNoMalloc-rc1-mergePoint`, `rc2-1-0-0`,
  `cyassl-1_0_3`, `fasthugemath`, `r1-4-4`. The last three plus
  `noMalloc-Merge-IO` are mixed-revision tags that match no single changeset;
  each points at its own parentless commit whose tree is the exact CVS tag
  state (as cvs-fast-export represents them).

Compared with the previous Software Heritage-derived layer (SWH Vault exports
`swh:1:rev:1e31aca5a98100ff2d36ff465b95c6fb25866af6` and
`swh:1:rev:3142ffdbe908b692a59bd28128e688d5cf739e08`, which also passed
`cvs export` at every one of its own commits): same timestamps, messages and
file contents at every SWH commit, plus

- 3 yaSSL commits SWH merged away, each holding a file revision that existed
  in no SWH commit: "test" 2006-03-29 02:58:36, "commit list test" 2006-05-14
  22:21:09 (README), "Add SSL_set_quiet_shutdown..." 2007-08-06 08:02:27
  (src/ssl.cpp);
- execute bits: SWH stored all files as 644; CVS has 755 on 41 yaSSL and 39
  CyaSSL files (`configure`, `config.guess`, `config.sub`, `depcomp`,
  `autogen.sh`, ...), matching the release tarballs;
- all CVS tags and branches (SWH kept only HEAD).

cvs-fast-export 2.5 problems found on these inputs (draft report, not filed:
`cfe-bug/DRAFT.md`): the vendor commit / `start` tag drops
the files never changed after import when run without a visible CVSROOT
(same symptom as closed GitLab issue #57); the `bNoMallocUpdate1` branch base
keeps 15 files CVS does not have there; one `cvs import` is split into 22-25
commits; and (Crypto++ `src`) trunk ignores later vendor imports for files
whose default branch is the vendor branch. File contents otherwise differ
from `cvs export` only by keyword expansion, which cvs-fast-export does not
do by design.

## Splice procedure

`tools/splice.py`: the rebuilt histories were
fetched into the repo; every commit outside the old CVS first-parent chain
with a parent inside it (CVS-era release side commits, yaSSL 2.3.7c, wolfSSL
"1.8.8 init") was regrafted onto the new trunk commit current at its
committer time (the same anchor rule as the original reposurgeon splice; all
60 anchors are content-identical to the old ones, differing only in execute
bits); the new import commit onto the last pre-CVS release; TomsFastMath onto
the new "add optional fast math and alloc overrides" commit. Then baked
(bake 4). The original 2026-10-02 reposurgeon splice of the SWH streams
(`unite --prune`, tree-preserving `reparent --use-order`) is
`tools/surgeryA-*.rs`, with anchors from `tools/anchors.py` and checks by
`tools/cvscheck.py`.

## Sources and selection rules

Per (product, version), the first available of: archive from the live
wolfssl.com web root (`server`), checksum-verified third-party mirror copy
(`gaps`: FreeBSD distcache, OpenWrt, SourceForge), the tree as imported into
MySQL (`mysql`, only when no vendor archive exists; may carry MySQL patches
and a different layout). When both .zip and .tar.gz exist the .zip is used
(only format after yassl 1.0.3, more complete; yassl .zip files use CRLF, the
early tarballs LF, so one line-ending churn appears at yassl 0.9.8). Alternate
copies and whether their extracted content is identical are in `catalog.tsv`.

Tree = archive contents with a single shared top-level folder stripped; empty
directories are dropped (git cannot store them). Commit author and committer:
Todd Ouska <todd@yassl.com>, date = release date at 12:00 UTC. Tagger is the builder identity.

Release date precedence (from gaps/dates.tsv): vendor README release-notes
date > earliest freecode/freshmeat announcement > newest file mtime in the
archive (lower bound) > earliest upper bound (distro import, SourceForge
upload, MySQL import). A date later than any upper bound is replaced by that
upper bound and marked CONFLICT. Dates not from README or freecode are weak.

## yaSSL and CyaSSL: related code, joined by an interpretive graft

In the real objects, `yassl` and `main` share no commits. yaSSL (C++) ended at
2.4.4 and did not become wolfSSL; wolfSSL descends from CyaSSL (C). The two are
still family:
CyaSSL's crypto layer, CTaoCrypt (`ctaocrypt/`), is a C sibling modeled on
yaSSL's TaoCrypt (`taocrypt/`). It is not a line-by-line port. Evidence,
comparing `yassl-1.2.2` with `cyassl-0.2.0`:

- Same author and company: both trees are copyright Sawtooth Consulting Ltd.
- Name and role: the CyaSSL 0.2.0 README introduces "CyaSSL and its crypt
  brother, CTaoCrypt".
- Module layout: every CTaoCrypt 0.2.0 source module (arc4, asn, coding,
  integer, md5, random, rsa, sha; des3 vs des) has a TaoCrypt counterpart.
- Shared ASN.1 sizing constants: `MAX_ALGO_SZ`, `MAX_SEQ_SZ`, `MAX_LENGTH_SZ`,
  `SHA_SIZE`.
- Different big-integer foundations: TaoCrypt `integer.cpp` is "based on Wei
  Dai's integer.cpp from CryptoPP"; CTaoCrypt `integer.c` is "Based on public
  domain LibTomMath 0.38".

No commit ever moved code from one tree to the other, so the link is a graft
(CyaSSL 0.2.0 -> yaSSL 1.1.5), not a synthetic commit. It is now a real parent
(see "Branches and refs"). The CyaSSL 0.2.0 commit's diff against yaSSL 1.1.5
is the C++ to C translation: TaoCrypt and the C++ SSL layer removed,
CTaoCrypt and CyaSSL added. `git blame` and `--follow` do not cross it,
because the C code was written fresh (different big-integer base, `.cpp` to
`.c`). Before the bake, the trees were unrelated in the real objects.

## Upstream library ancestry

Both crypto layers started from someone else's big-integer code, and CyaSSL's
ECC came from LibTomCrypt. Each upstream release is an extra (second) parent
of the commit that imported it, fetched from the upstream git repos with
history up to that tag only:

| Upstream (repo, tag) | Commits | Grafted onto | Evidence |
|---|---|---|---|
| Crypto++ 5.1, Wei Dai (`weidai11/cryptopp` `CRYPTOPP_5_1`, upstream `b2f710a95`, here `67c42df98`, 2003-03-22) | 48 | yaSSL 0.2.0 `e45633e49` (second parent; first parent is yaSSL 0.0.3) | yaSSL 0.2.0 ships `cryptopp51/crypto51.zip`; 309 of 310 files equal the tag tree (only `crypto++.mcp`, a binary CodeWarrior project, differs) |
| LibTomMath 0.38, Tom St Denis (`libtom/libtommath` `0.38`, `21adca01d`, 2006-01-26) | 38 | CyaSSL 0.2.0 `7b23622e9` | `integer.c`: "Based on public domain LibTomMath 0.38"; `mpi_class.h` differs from `tommath_class.h` in 7 of 999 lines |
| TomsFastMath 0.10, Tom St Denis (`libtom/tomsfastmath` `0.10`, `ea10e969b`, 2006-11-01) | 10 | CyaSSL CVS "add optional fast math and alloc overrides" `2c313f7fd` (2008-07-24, adds `tfm.c`) | `tfm.c`: "Based on public domain TomsFashMath 0.10" [sic] |
| LibTomCrypt 1.17, Tom St Denis (`libtom/libtomcrypt` `1.17`, `bbc52b9e1`, 2007-07-20) | 45 | wolfSSL "fix gcc lots o warnings for optional library build features" `389f2c4ab` (2011-04-28, upstream wolfSSL `1ce566971`; adds the 1517-line `ecc.c` body despite the message) | No attribution in `ecc.c`. LibTomCrypt fingerprints: `ecc_sets[]` with "ECC-192".."ECC-521" names, `ecc_projective_add_point`, `ecc_projective_dbl_point`, `ecc_map` (LibTomCrypt's `ltc_`-prefixed functions). Version is a best match, not proof: after normalizing `ltc_`/`CRYPT_OK` naming, `ecc.c` shares 127 lines with 1.17's ECC sources vs 126 with 1.16 and 1.18.0, and matches one line unique to 1.17 against each neighbour and none unique to either; 1.17 was also the current release in 2011 (1.18 shipped 2017) |

Licenses, from each tag's own file: Crypto++ 5.1 is a compilation copyright
by Wei Dai with the individual files in the public domain (except
`mars.cpp`); LibTomMath, TomsFastMath and LibTomCrypt 1.17 are public domain.

The merges carry attribution, not content: each merge's tree is the
yaSSL/CyaSSL tree, unchanged. `git blame` does not cross them; LibTomMath's
separate `bn_*.c` files were concatenated into one `integer.c`, and TaoCrypt's
`integer.cpp` was reworked. Releases after these (e.g. later LibTomMath or
TomsFastMath fixes wolfSSL may have pulled in) are not grafted.

Crypto++ 5.1 covers more than bignum: by yaSSL 1.2.2, TaoCrypt files cite
"Wei Dai's X from CryptoPP" for aes, aestables, algebra, arc4, bfinit,
blowfish, des, integer, md2, md5, misc, modarith, ripemd, rsa, sha, tftables
and twofish. yaSSL 0.2.0's `crypto/Readme.txt` instead claims "Copyright (C)
2003 Sawtooth Consulting" for every file in `crypto/`; the per-file Crypto++
credits appear in later releases.

## Crypto++ CVS history

Source: SourceForge raw CVS snapshot
<https://sourceforge.net/code-snapshots/cvs/c/cr/cryptopp.zip> (3,342,544
bytes, sha256 `55c4d3a26695be533d1d5797334319f811d1e3d889d0bc85f549558740b4d6b2`),
modules `src` (Crypto++ 3.2 to 4.2, 2000-06-26 to 2002-12-12) and `c5` (5.0 on).
The upstream git history (weidai11/cryptopp, via cvs2svn and SourceForge SVN)
matches this CVS and SVN exactly for all 48 commits up to `CRYPTOPP_5_1`
(`reports/cryptopp-vs-sourceforge.md`), but lacks `src`
entirely and flattens the `c50-fixes` branch into empty commits.

`src` keeps its main line on the vendor branch: three `cvs import`s of release
snapshots (2000-06-26 05:33, 2000-06-26 06:12, 2000-10-27 09:35) onto vendor
branch `WEIDAI`, then ordinary trunk commits. CVS treats a file whose only
trunk revision is the import as following the vendor branch; cvs-fast-export
2.5 does not, so its trunk keeps those files at 1.1 and never reaches the
`CRYPTOPP_4_1` or `CRYPTOPP_4_2` states. The trunk here is therefore built by
sampling (`tools/build_sampled.py`): each
cvs-fast-export changeset supplies a time and metadata, and its tree is
`cvs export -D <time>`; each import burst is one commit with the vendor
import's message and time. 46 commits (3 imports, 43 changesets). Checks:
release tags `CRYPTOPP_3_2`, `CRYPTOPP_4_1`, `CRYPTOPP_4_2` (exact per-file
revisions, no date logic) each equal a trunk state; the tip equals
`cvs export -r HEAD` and cvs-fast-export's tip. `CRYPTOPP_4_0` and `start`
are mixed-revision tags and the vendor branch tip `WEIDAI` matches no trunk
state; each points at its own parentless commit with the exact CVS tree.

`c5` refs added on the existing 5.0 history: `c50-fixes` (2002-12-06 to
2003-03-10): a branch-base commit with the exact CVS branch-point tree (mixed:
16 files away from the nearest trunk commit), parented on the 5.0 import as
cvs-fast-export does, then 4 commits sampled with
`cvs export -r c50-fixes -D <time>`. All 5 trees equal SourceForge SVN
`branches/c50-fixes` at r22, r23, r25, r29, r36 (cvs2svn's independent
conversion). `c50-fixes-merged` is the branch tip; `CRYPTOPP_5_0` and vendor
branch `WEIDAI` are the 5.0 import.

## yaSSL 0.0.2 and 0.0.3

No full 0.0.x release survives. The 0.0.1 download was a "complete build"
that bundled CryptoPP, CML (the Certificate Management Library) and a
`buildall` script; 0.0.2 and 0.0.3 were also published as update archives
(`yassl-update-0.0.2.tar.gz`, `yassl-update-0.0.3.tar.gz`, from the wolfssl.com
web root, Freshmeat dates 2004-03-18 and 2004-03-29) that overwrite all of
yaSSL's own code: the same 26 files each time (10 `src/`, 15 `include/`,
`Readme.txt`), all of yaSSL's source of that era (the full 0.2.0 adds only 4
OpenSSL-compatibility headers to `src/` and `include/`). They are not diffs, so
they cannot be reversed to recover 0.0.1 or 0.1.0.

Tags `yassl-0.0.2` and `yassl-0.0.3` (`Kind: source-only (update archive)`)
point at commits whose trees are those archives' bytes exactly (verified
against an independent extraction). The archives store every file as mode
0777 (made on Windows); modes are normalized to 100644, as in the full 0.2.0
release. 0.0.2 is a root commit, 0.0.3 its child, and yaSSL 0.2.0 has parents
0.0.3 (first) and Crypto++ 5.1. The 0.0.3 to 0.2.0 diff therefore shows the
build system, certificates, `crypto/`, `stunnel/` and the bundled archives as
added; that reflects what the update archives omitted, not what 0.2.0 added.
11 of the 26 files are byte-identical in 0.0.3 and 0.2.0. Script:
`tools/add_000x.py`.

## Third-party code not grafted

No usable upstream git history, or not part of the library:

| Code | Source | First release | Credited in file |
|---|---|---|---|
| `stunnel/` | stunnel 4.05, Michal Trojnara (GPL), with one mod_ssl-derived function; bundled port demo | yassl-0.2.0 | yes |
| `rabbit.c` | eSTREAM Rabbit reference code (keeps its `U32V()` macro) | cyassl-1.0.0rc2 | no |
| `hc128.c` | presumed eSTREAM HC-128 reference (Hongjun Wu); no fingerprint found | cyassl-1.0.0rc2 | no |
| `camellia.c` | NTT Camellia reference 1.2.0 (BSD) | cyassl-2.5.0 | yes (NTT copyright) |
| `blake2b.c` | BLAKE2 reference, Samuel Neves (CC0) | cyassl-2.6.0 | yes |
| `chacha.c` | D. J. Bernstein `chacha-ref.c` 20080118 | cyassl-3.2.0 | yes |
| `poly1305.c` | Andrew Moon / D. J. Bernstein public-domain code | cyassl-3.2.0 | yes |

CTaoCrypt's md5, sha, des3, arc4, aes and hmac carry no outside attribution;
they are presumably C rewrites of TaoCrypt (so second-hand Crypto++), not
verified line by line.

## Gaps and caveats

- Weak dates: cyassl-2.3.1, cyassl-3.2.0, cyassl-3.3.0, yassl-0.9.7, yassl-1.4.2, yassl-1.4.3, yassl-1.6.5, yassl-1.8.0, yassl-2.1.4, yassl-2.2.0, yassl-2.2.3b, yassl-2.3.9, yassl-2.3.9b, yassl-2.4.0, yassl-2.4.2, yassl-2.4.4
- Versions known from dates evidence but with no archive anywhere: cyassl-0.5.1, cyassl-0.5.5, cyassl-0.6.0, cyassl-0.6.3, cyassl-0.9.9e, cyassl-3.0.2, yassl-0.0.1, yassl-0.1.0, yassl-2.1.2, yassl-2.2.1
- yassl-1.8.0.zip as served (and as captured by Wayback in 2016) is damaged:
  a stray byte shifts local headers. All entries except `configure` were
  recovered with valid CRC-32; `configure` (generated by autoconf) is omitted.
- yassl-update-0.0.2 and 0.0.3 are committed as source-only releases (see
  "yaSSL 0.0.2 and 0.0.3"); yassl-update-0.2.0 and 0.2.9 are cataloged, not
  committed, since the full 0.2.0 and 0.2.9 releases exist.
- taocrypt standalone and wolfssl 3.x archives are cataloged only; wolfSSL git
  covers wolfssl 3.x.
- CyaSSL releases dated on/after 2011-02-05 are tagged on wolfSSL commits only
  where wolfSSL has a matching tag; see `lineage` column in catalog.tsv.

## Bake verification (2026-10-02)

Sixth bake (yaSSL 0.0.2/0.0.3): no replace refs left; all 159 refs have the
same trees as in the grafted state; branch commit counts unchanged from it
(`main` 32132 and `yassl` 333, each +2); `main` tree equals upstream wolfSSL
`0bcda7efa2ec`; `git fsck --full --strict` is clean.

Fifth bake (Crypto++ CVS history, graft 4): no replace refs left; all 157
refs have the same trees as in the grafted state; branch commit counts
unchanged from it (`main` 32130 = 32086 + 44 `src` commits up to the fork);
`main` tree equals upstream wolfSSL `0bcda7efa2ec`; LibTom tags kept their
IDs; `git fsck --full --strict` is clean.

Fourth bake (CVS layer rebuild), against its pre-bake mirror (since deleted):
no replace refs left; all 146 refs (4 branches + 6 CVS branches, 125 release
and upstream tags + 11 CVS tags) have the same trees as in the grafted state;
the old ref trees are unchanged except `cyassl`, whose tip differs from the
old tip only in execute bits; `main` 32086 (unchanged: it reaches yaSSL only
through 1.1.5, before CVS), `yassl` 287 (+3 recovered commits), `cyassl`
327; `main` tree equals upstream wolfSSL `0bcda7efa2ec`; all four upstream
tags kept their commit IDs; CVS layers re-verified against `cvs export`
(201/201, 200/200, 17/17 refs); `git fsck --full --strict` is clean.

Third bake (LibTomCrypt), against its pre-bake mirror (since deleted):
no replace refs left; all 129 refs have unchanged trees; branch commit counts
unchanged from the grafted state (`main` 32086 = 32041 + 45); all four
upstream tags kept their commit IDs; `git fsck --full --strict` is clean.

Second bake (bignum part of graft 3), against its pre-bake mirror (since
deleted): no
replace refs left; all 128 refs (4 branches, 124 tags) have unchanged trees;
branch commit counts unchanged from the grafted state (`main` 32041 = 31945
+ 48 + 38 + 10); the three upstream tags kept their commit IDs;
`git fsck --full --strict` is clean.

First bake (grafts 1-2), against its pre-bake mirror (since deleted): no replace refs left; `main` has 31945 commits
and its tree equals wolfSSL `master`; the tips of `main`, `yassl`, `cyassl`
and `notes` have unchanged trees; all 121 release tags have unchanged trees;
`git fsck --full --strict` is clean. filter-repo split annotated tags stored
outside `refs/tags/` into duplicate `refs/tags/refs/pre-cvs/tags/*` refs and
left one fallback ref on an unrewritten commit; that is why the fallback was
dropped here; the copy in the mirror was deleted with it.

## Files on this branch

- `LINEAGE.md` (this file), `catalog.tsv` (every archive considered: source,
  sha256, release date and basis, how it was used).
- `commit-map.txt`: original commit ID to current ID, chained across all bakes.
- `tools/`: `build_lineage.py` and `verify_lineage.py` (release snapshots);
  `anchors.py`, `cvscheck.py`, `surgeryA-*.rs` (original reposurgeon splice);
  `build_cvs.py`, `build_sampled.py`, `splice.py`, `refcheck.sh`,
  `trunkcheck.sh` (CVS rebuild from SourceForge and its checks);
  `add_000x.py` (yaSSL 0.0.2/0.0.3); `authors.map`. They are records of how
  this repository was built; paths inside them refer to the builder's
  machine. Inputs (release archives, SourceForge CVS zips) are not stored here;
  `catalog.tsv` and the sections above give their URLs and sha256.
- `reports/`: Crypto++ git vs SourceForge CVS/SVN; LibTom grafts vs signed
  release tarballs.
- `cfe-bug/`: unfiled draft report of cvs-fast-export 2.5 problems found
  here, with stripped RCS repros.

## Provenance of the snapshot layer

The release snapshots were built by `tools/build_lineage.py`
and verified by verify_lineage.py (independent extraction of each archive vs
`git archive <tag>`). The CVS layer was added afterwards (see "CVS history"
and "Splice procedure"); the builder's own CVS path was not used.
