# wolfssl-lineage

Reconstructed history of yaSSL (C++, 2004-2017), CyaSSL (C, 2006-2011) and
its continuation wolfSSL (git from 2011-02-05), plus the upstream bignum
libraries they were built on (Crypto++, LibTomMath, TomsFastMath). Local
reconstruction; not an official wolfSSL repository.

## Branches and refs

- `yassl`: yaSSL releases 0.2.0..1.2.2 as snapshots, then the yaSSL CVS history
  (198 commits, 2006-03-28 "yaSSL 1.2.2 cvs import" .. 2015-03-18), then
  releases 2.3.7c..2.4.4 as snapshots. 236 commits on the branch line.
- `cyassl`: CyaSSL releases 0.2.0..0.5.0 as snapshots, then the CyaSSL CVS
  history (200 commits, 2006-04-05 "cyassl 0.5.1 cvs import" .. 2011-01-06).
  204 commits on the branch line.
- `main`: wolfSSL `master` with the grafts below baked in. Its tree equals
  wolfSSL `master`, but every yaSSL, CyaSSL and wolfSSL commit ID is rewritten,
  so `main` commit IDs do NOT match upstream wolfSSL. Translate with
  `.git/filter-repo/commit-map` (old ID, new ID per line). filter-repo chained
  the two bakes, so its keys are the original IDs (upstream wolfSSL, and the
  first snapshot/CVS build) and its values are the current IDs; e.g. wolfSSL
  "1.8.8 init" `6b88eb05b` is `17c7acc5c905` here.
- `notes`: this file plus `catalog.tsv`, on an orphan branch.
- Graft 1 (permanent): wolfSSL's root commit "1.8.8 init" (2011-02-05,
  `17c7acc5c905`) is a child of the `cyassl` tip, the last CyaSSL CVS commit
  (2011-01-06, `79be995f69e3`; originally `adc5a5503`).
- Tags `yassl-<ver>`, `cyassl-<ver>`: annotated. Release tags whose `Kind:` is
  `snapshot` have tree == release archive (byte-identical, verified). Releases
  dated inside a CVS window are side commits: the exact archive tree, parented
  on the last CVS commit at or before the release date, so the branch line
  stays pure CVS and each release shows where it forked. Releases before or
  after the CVS window are on the branch line. `wolfssl-tag` tags sit on
  wolfSSL commits carrying the matching wolfSSL `v<ver>` tag.
- Graft 2 (permanent, interpretive): CyaSSL 0.2.0 (2006-02-19, `915cda82b295`;
  originally `85faa773e`) is a child of yaSSL 1.1.5 (2006-01-09,
  `b8fd98215af7`, originally `4dcebc25b`, the yaSSL release current at the
  time). `git merge-base yassl main` is yaSSL 1.1.5.
  This records lineage, not code flow; see "yaSSL and CyaSSL" below.
- Graft 3 (permanent): upstream bignum libraries as extra merge parents on
  the commits that imported them, plus LibTomCrypt (ECC) the same way; see
  "Upstream library ancestry" below.
  `git log main` therefore runs back to the Crypto++ 5.0 import (2002-10-04);
  `git log --first-parent main` stays on the yaSSL/CyaSSL/wolfSSL line.
- Tags `cryptopp-5.1`, `libtommath-0.38`, `tomsfastmath-0.10`,
  `libtomcrypt-1.17`: the upstream annotated tags (`CRYPTOPP_5_1`, `0.38`,
  `0.10`, `1.17`), renamed.
- All grafts were baked in on 2026-10-02: grafts 1-2 (first bake), the
  bignum part of graft 3 (second bake), LibTomCrypt (third bake). Each was
  first a replace ref, then baked with
  `git filter-repo --proceed --force --replace-refs delete-no-add` (second and
  third bakes also `--prune-empty never --prune-degenerate never`). No replace
  refs remain; a plain clone shows the full history. Upstream library commits
  and `notes` keep their IDs.
- Pre-bake state: `~/GIT/wolfssl-lineage-pre-bake.git` (mirror) holds the
  repo before the first bake, with grafts 1-2 as replace refs, the original
  wolfSSL commit IDs, and the `refs/pre-cvs/*` snapshot-only fallback from
  before the CVS splice (those fallback refs were dropped from this repo).
  `~/GIT/wolfssl-lineage-pre-bignum.git` (mirror) holds the repo between the
  first two bakes; its `filter-repo-run1/commit-map` is the first bake's map.
  `~/GIT/wolfssl-lineage-pre-libtomcrypt.git` (mirror) holds the repo between
  the second and third bakes, with that map in `filter-repo-run2/`.

## CVS history

Source: Software Heritage archive of the old SourceForge CVS repositories,
fetched as Vault git-bare exports of yaSSL `swh:1:rev:1e31aca5a98100ff2d36ff465b95c6fb25866af6`
(snapshot `swh:1:snp:11570859eba21613988dddfd9cf6da8b36fe1ddb`) and CyaSSL
`swh:1:rev:3142ffdbe908b692a59bd28128e688d5cf739e08` (snapshot
`swh:1:snp:b0580dbd109bb966d6c304cb76b9d61e0fd2978a`).

The SWH conversion has CVS user names with no email (`author touska <ts>`),
which git fsck rejects. Each line was rewritten to `touska <touska>` and then
mapped by reposurgeon `authors read`:

    touska      = Todd Ouska <todd@yassl.com>
    chrisconlon = Chris Conlon <chris@wolfssl.com>
    myassl      = myassl <myassl@users.sourceforge.net>
    uid182869   = uid182869 <uid182869@users.sourceforge.net>

Timestamps, messages and file contents are unchanged. 127 yaSSL SWH commits
carry an empty `mySTL/` directory (CVS cannot remove directories); git cannot
store empty directories, so it is absent here. Every CVS commit was verified
file-by-file (path, mode, blob) against the SWH original: 198/198 and 200/200.

## Splice procedure (reposurgeon)

Per product, inputs were the snapshot branch plus its release tags, and the
SWH CVS export as a fast-export stream. Script, run once:

    read <snap.fi
    read <swh.fi
    unite --prune snap swh          # CVS root grafted on last pre-CVS release;
                                    # --prune keeps CVS trees exact
    authors read <authors.map
    <anchor>,<release> reparent --use-order    # per CVS-era release
    <cvs-head>,<first post-CVS release> reparent --use-order   # yassl only
    write >united.fi

`reparent` without `--rebase` preserves the reparented commit's tree, so every
release tag tree is unchanged (verified against the pre-splice tags: 100/100).
Work files: ~/TASKS/yassl-lineage/surgery/.

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
`.c`). The pre-bake mirror shows the trees as unrelated with
`git --no-replace-objects`.

## Upstream library ancestry

Both crypto layers started from someone else's big-integer code, and CyaSSL's
ECC came from LibTomCrypt. Each upstream release is an extra (second) parent
of the commit that imported it, fetched from the upstream git repos with
history up to that tag only:

| Upstream (repo, tag) | Commits | Grafted onto | Evidence |
|---|---|---|---|
| Crypto++ 5.1, Wei Dai (`weidai11/cryptopp` `CRYPTOPP_5_1`, `b2f710a95`, 2003-03-22) | 48 | yaSSL 0.2.0 `cbcf661b5` (was a root commit) | yaSSL 0.2.0 ships `cryptopp51/crypto51.zip`; 309 of 310 files equal the tag tree (only `crypto++.mcp`, a binary CodeWarrior project, differs) |
| LibTomMath 0.38, Tom St Denis (`libtom/libtommath` `0.38`, `21adca01d`, 2006-01-26) | 38 | CyaSSL 0.2.0 `915cda82b` | `integer.c`: "Based on public domain LibTomMath 0.38"; `mpi_class.h` differs from `tommath_class.h` in 7 of 999 lines |
| TomsFastMath 0.10, Tom St Denis (`libtom/tomsfastmath` `0.10`, `ea10e969b`, 2006-11-01) | 10 | CyaSSL CVS "add optional fast math and alloc overrides" `eaa612b89` (2008-07-24, adds `tfm.c`) | `tfm.c`: "Based on public domain TomsFashMath 0.10" [sic] |
| LibTomCrypt 1.17, Tom St Denis (`libtom/libtomcrypt` `1.17`, `bbc52b9e1`, 2007-07-20) | 45 | wolfSSL "fix gcc lots o warnings for optional library build features" `6567ee3c8` (2011-04-28, upstream wolfSSL `1ce566971`; adds the 1517-line `ecc.c` body despite the message) | No attribution in `ecc.c`. LibTomCrypt fingerprints: `ecc_sets[]` with "ECC-192".."ECC-521" names, `ecc_projective_add_point`, `ecc_projective_dbl_point`, `ecc_map` (LibTomCrypt's `ltc_`-prefixed functions). Version is a best match, not proof: after normalizing `ltc_`/`CRYPT_OK` naming, `ecc.c` shares 127 lines with 1.17's ECC sources vs 126 with 1.16 and 1.18.0, and matches one line unique to 1.17 against each neighbour and none unique to either; 1.17 was also the current release in 2011 (1.18 shipped 2017) |

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
- Versions known from dates evidence but with no archive anywhere: cyassl-0.5.1, cyassl-0.5.5, cyassl-0.6.0, cyassl-0.6.3, cyassl-0.9.9e, cyassl-3.0.2, yassl-0.0.1, yassl-0.0.2, yassl-0.0.3, yassl-0.1.0, yassl-2.1.2, yassl-2.2.1
- yassl-1.8.0.zip as served (and as captured by Wayback in 2016) is damaged:
  a stray byte shifts local headers. All entries except `configure` were
  recovered with valid CRC-32; `configure` (generated by autoconf) is omitted.
- yassl-update-* tarballs are partial updates; cataloged, not committed.
- taocrypt standalone and wolfssl 3.x archives are cataloged only; wolfSSL git
  covers wolfssl 3.x.
- CyaSSL releases dated on/after 2011-02-05 are tagged on wolfSSL commits only
  where wolfSSL has a matching tag; see `lineage` column in catalog.tsv.

## Bake verification (2026-10-02)

Third bake (LibTomCrypt), against `~/GIT/wolfssl-lineage-pre-libtomcrypt.git`:
no replace refs left; all 129 refs have unchanged trees; branch commit counts
unchanged from the grafted state (`main` 32086 = 32041 + 45); all four
upstream tags kept their commit IDs; `git fsck --full --strict` is clean.

Second bake (bignum part of graft 3), against `~/GIT/wolfssl-lineage-pre-bignum.git`: no
replace refs left; all 128 refs (4 branches, 124 tags) have unchanged trees;
branch commit counts unchanged from the grafted state (`main` 32041 = 31945
+ 48 + 38 + 10); the three upstream tags kept their commit IDs;
`git fsck --full --strict` is clean.

First bake (grafts 1-2), against the pre-bake mirror: no replace refs left; `main` has 31945 commits
and its tree equals wolfSSL `master`; the tips of `main`, `yassl`, `cyassl`
and `notes` have unchanged trees; all 121 release tags have unchanged trees;
`git fsck --full --strict` is clean. filter-repo split annotated tags stored
outside `refs/tags/` into duplicate `refs/tags/refs/pre-cvs/tags/*` refs and
left one fallback ref on an unrewritten commit; that is why the fallback was
dropped here and kept only in the mirror.

## Provenance of the snapshot layer

The release snapshots were built by ~/TASKS/yassl-lineage/build/build_lineage.py
and verified by verify_lineage.py (independent extraction of each archive vs
`git archive <tag>`). The CVS layer was added afterwards by the reposurgeon
splice above; the builder's own CVS path was not used.
