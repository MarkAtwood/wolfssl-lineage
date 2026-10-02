# wolfssl-lineage

Reconstructed history of yaSSL (C++, 2004-2017), CyaSSL (C, 2006-2011) and
its continuation wolfSSL (git from 2011-02-05). Local reconstruction; not an
official wolfSSL repository.

## Branches and refs

- `yassl`: yaSSL releases 0.2.0..1.2.2 as snapshots, then the yaSSL CVS history
  (198 commits, 2006-03-28 "yaSSL 1.2.2 cvs import" .. 2015-03-18), then
  releases 2.3.7c..2.4.4 as snapshots. 236 commits on the branch line.
- `cyassl`: CyaSSL releases 0.2.0..0.5.0 as snapshots, then the CyaSSL CVS
  history (200 commits, 2006-04-05 "cyassl 0.5.1 cvs import" .. 2011-01-06).
  204 commits on the branch line.
- `main`: wolfSSL `master` with the grafts below baked in. Its tree equals
  wolfSSL `master`, but every commit ID from CyaSSL 0.2.0 onward is rewritten,
  so `main` commit IDs do NOT match upstream wolfSSL. Translate with
  `.git/filter-repo/commit-map` (old ID, new ID per line); e.g. wolfSSL
  "1.8.8 init" `6b88eb05b` is `c2031a6c1cf8` here.
- `notes`: this file plus `catalog.tsv`, on an orphan branch.
- Graft 1 (permanent): wolfSSL's root commit "1.8.8 init" (2011-02-05,
  `c2031a6c1cf8`) is a child of the `cyassl` tip, the last CyaSSL CVS commit
  (2011-01-06, `900d94aea534`; was `adc5a5503`).
- Tags `yassl-<ver>`, `cyassl-<ver>`: annotated. Release tags whose `Kind:` is
  `snapshot` have tree == release archive (byte-identical, verified). Releases
  dated inside a CVS window are side commits: the exact archive tree, parented
  on the last CVS commit at or before the release date, so the branch line
  stays pure CVS and each release shows where it forked. Releases before or
  after the CVS window are on the branch line. `wolfssl-tag` tags sit on
  wolfSSL commits carrying the matching wolfSSL `v<ver>` tag.
- Graft 2 (permanent, interpretive): CyaSSL 0.2.0 (2006-02-19, `5ac328bb489a`;
  was `85faa773e`) is a child of yaSSL 1.1.5 (2006-01-09, `4dcebc25b`, the
  yaSSL release current at the time). `git log main` therefore runs back to
  yaSSL 0.2.0 (2004-06-28), and `git merge-base yassl main` is yaSSL 1.1.5.
  This records lineage, not code flow; see "yaSSL and CyaSSL" below.
- Both grafts were first added as replace refs, then baked in on 2026-10-02
  with `git filter-repo --proceed --force --replace-refs delete-no-add`. No
  replace refs remain; a plain clone shows the full history. yaSSL commits
  (whose parents did not change) and `notes` kept their IDs.
- Pre-bake state: `~/GIT/wolfssl-lineage-pre-bake.git` (mirror) holds the
  repo as it was before the rewrite, with both grafts as replace refs, the
  original wolfSSL commit IDs, and the `refs/pre-cvs/*` snapshot-only fallback
  from before the CVS splice. Those fallback refs were dropped from this repo.

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

Against the pre-bake mirror: no replace refs left; `main` has 31945 commits
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
