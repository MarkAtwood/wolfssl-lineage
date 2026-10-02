# LibTom grafts vs original release tarballs (2026-10-02)

Verdict: all three grafted commits match their signed release tarballs, modulo
three artifacts of the upstream libtom git import: tarball top-level directory
stripped; `CVS/{Entries,Repository,Root}` dirs (ltm-0.38, tfm-0.10) not
imported; CVS keywords collapsed in git (`$Source: ...$` -> `$Source$`,
`$Revision$`, `$Date$`; 4 files `$Id: ...$` -> `$ID$`). No CRLF, mode, git-only,
or unexplained content differences. Grafted commit trees equal the upstream
GitHub trees.

## Sources and checksum provenance

Each tarball: Wayback capture of the author's site, plus (1) good detached PGP
signature by Tom St Denis, key `D63E E520 DE88 7CD1 8975 5341 B0FF AD12 C1C7 6340`
(fetched from keyserver.ubuntu.com, not WoT-validated), and (2) SHA256 + size
matching the FreeBSD ports `distinfo` of the version-bump commit.

| Release | SHA256 | Size | Signed (UTC) | FreeBSD distinfo commit |
|---|---|---|---|---|
| ltm-0.38.tar.bz2 | `c4ef4a47146b8d3b642c4d64d02d77d7c428fd794482a4e998a0840b8c5a9d29` | 1924687 | 2006-01-26 04:06 | `4ae496ff` math/libtommath, 2006-02-06 |
| tfm-0.10.tar.bz2 | `699a60a623017c2836576612ebca690144816ca8d48df68fb7d819f6b21a9e22` | 229623 | 2006-11-01 08:41 | `c8176027` math/tomsfastmath, 2006-11-30 |
| crypt-1.17.tar.bz2 | `e33b47d77a495091c8703175a25c8228aff043140b2554c08a3c3cd71f79d116` | 1599215 | 2007-05-12 14:46 | `1aa1f77a` security/libtomcrypt, 2007-06-22 |

- ltm-0.38: `https://web.archive.org/web/20060630034350id_/http://math.libtomcrypt.com:80/files/ltm-0.38.tar.bz2` (+ `.asc` at `20060630035426id_`)
- tfm-0.10: `https://web.archive.org/web/20070222195938id_/http://libtom.org:80/files/tfm-0.10.tar.bz2` (+ `.asc` at `20070222200406id_`); mirror.libtom.org copy identical
- crypt-1.17: `https://web.archive.org/web/20070609085705id_/http://libtom.org/files/crypt-1.17.tar.bz2` (+ `.asc` at `20070609085650id_`); mirror.libtom.org, FreeBSD distcache and GitHub release copies byte-identical
- Gentoo and pkgsrc distfiles: 404.

Dates: ltm-0.38 and tfm-0.10 git commit dates are about an hour before their
signature times. The libtomcrypt-1.17 git commit is dated 2007-07-20, about two
months after the signed release (2007-05-12) and the 2007-06-09 Wayback capture.
Use 2007-05-12 as the 1.17 release date.

## Comparison (git blob hash + mode per path, tarball top dir stripped)

| | libtommath-0.38 | tomsfastmath-0.10 | libtomcrypt-1.17 |
|---|---|---|---|
| files tarball / git | 223 / 199 | 140 / 122 | 393 / 393 |
| tarball-only | 24, all `CVS/*` | 18, all `CVS/*` | 0 |
| git-only / mode diffs | 0 / 0 | 0 / 0 | 0 / 0 |
| byte-identical | 62 | 57 | 56 |
| identical after keyword collapse | 134 | 65 | 336 |
| identical after `$Id: ...$` -> `$ID$` | 3 | 0 | 1 |
| unexplained | 0 | 0 | 0 |

Keyword lines are comments only; no compiled code differs. Files: tarballs,
signatures, key, `compare.py`, `keyword_check.py`, `compare-*.txt`,
`keyword-check-*.txt` in this directory.
