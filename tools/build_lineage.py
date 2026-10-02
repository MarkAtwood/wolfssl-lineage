#!/usr/bin/env python3
"""Build a local git repo reconstructing the yaSSL -> CyaSSL -> wolfSSL lineage.

Usage:
  build_lineage.py OUT_REPO [--force-rebuild OUT_REPO] [--swh-dir DIR]
                   [--wolfssl DIR] [--catalog-only]

Inputs live under ~/TASKS/yassl-lineage (see LINEAGE_ROOT). CVS history is
used when bare git repos exist at <swh-dir>/yassl and <swh-dir>/cyassl;
otherwise release snapshots are used throughout. The output repo has no
remotes. wolfSSL history is joined with `git replace --graft`.
"""
import argparse
import collections
import copy
import csv
import datetime
import glob
import hashlib
import os
import shutil
import re
import stat
import subprocess
import sys
import tarfile
import zlib
import zipfile

LINEAGE_ROOT = os.path.expanduser("~/TASKS/yassl-lineage")
BUILD_DIR = os.path.join(LINEAGE_ROOT, "build")
WOLFSSL_ROOT_ABBREV = "6b88eb05b"
YASSL_CVS_START, YASSL_CVS_END = "2006-03-28", "2015-03-18"
CYASSL_CVS_START, CYASSL_CVS_END = "2006-04-05", "2011-01-06"
WOLFSSL_GIT_START = "2011-02-05"
CVS_MATCH_WINDOW_DAYS = 7
# ponytail: fixed "close match" threshold; a CVS commit within this many
# differing tracked files (CRLF-normalized) is the release, else a side commit
# with the exact archive tree is kept too.
CVS_CLOSE_MAX_DIFF = 2

AUTHOR = "Todd Ouska <todd@yassl.com>"
TAGGER = "wolfssl-lineage builder <lineage@invalid>"
csv.field_size_limit(sys.maxsize)


def die(msg):
    sys.exit("build_lineage: " + msg)


def run(args, cwd=None, input=None, env=None, check=True):
    p = subprocess.run(args, cwd=cwd, input=input, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode != 0:
        die("command failed (%d): %s\n%s" % (p.returncode, " ".join(args),
                                            p.stderr.decode(errors="replace")))
    return p


def git(repo, *args, **kw):
    return run(["git", "-C", repo] + list(args), **kw)


def git_out(repo, *args):
    return git(repo, *args).stdout.decode().strip()


# ---------------------------------------------------------------- versions

def norm_version(v):
    m = re.match(r"^rc(\d+)-(.*)$", v)
    return "%src%s" % (m.group(2), m.group(1)) if m else v


def version_key(v):
    m = re.match(r"^(\d+(?:\.\d+)*)(rc\d+|[a-z])?$", v)
    if not m:
        die("unparseable version %r" % v)
    nums = [int(x) for x in m.group(1).split(".")]
    nums += [0] * (3 - len(nums))
    suf = m.group(2) or ""
    if suf.startswith("rc"):
        return (nums, -1, int(suf[2:]))
    return (nums, ord(suf) if suf else 0, 0)


# ---------------------------------------------------------------- archives

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_path(name):
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or ".." in parts or ".git" in parts:
        return None
    return "/".join(parts)


def read_zip_entry(z, info):
    """Read one entry, CRC-checked. yassl-1.8.0.zip as served has a stray
    byte shifting some local headers by one, so retry at offset +/-1."""
    for delta in (0, 1, -1):
        shifted = copy.copy(info)
        shifted.header_offset = info.header_offset + delta
        try:
            return z.read(shifted)
        except (zipfile.BadZipFile, zlib.error):
            continue
    return None


def read_archive(path):
    """Return (files, notes): files maps relpath -> (gitmode, bytes) with a
    single shared top-level directory stripped."""
    raw, notes = {}, []
    if path.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                p = safe_path(info.filename)
                if p is None:
                    notes.append("skipped unsafe entry %r" % info.filename)
                    continue
                umode = info.external_attr >> 16
                data = read_zip_entry(z, info)
                if data is None:
                    notes.append("DAMAGED: unrecoverable entry %s (CRC fails at every offset), omitted" % p)
                    continue
                if info.create_system == 3 and stat.S_ISLNK(umode):
                    mode = "120000"
                elif info.create_system == 3 and umode & 0o111:
                    mode = "100755"
                else:
                    mode = "100644"
                if p in raw:
                    notes.append("duplicate entry %s" % p)
                raw[p] = (mode, data)
    else:
        with tarfile.open(path) as t:
            for m in t.getmembers():
                if m.isdir():
                    continue
                p = safe_path(m.name)
                if p is None:
                    notes.append("skipped unsafe entry %r" % m.name)
                    continue
                if m.issym():
                    raw[p] = ("120000", m.linkname.encode())
                elif m.isfile():
                    data = t.extractfile(m).read()
                    raw[p] = ("100755" if m.mode & 0o111 else "100644", data)
                elif m.islnk():
                    notes.append("hardlink %s -> %s" % (p, m.linkname))
                    tgt = safe_path(m.linkname)
                    if tgt in raw:
                        raw[p] = raw[tgt]
                else:
                    notes.append("skipped special entry %s" % p)
    tops = {p.split("/", 1)[0] for p in raw}
    if len(tops) == 1 and all("/" in p for p in raw):
        top = tops.pop() + "/"
        notes = [n.replace("entry " + top, "entry ", 1) for n in notes]
        return {p[len(top):]: v for p, v in raw.items()}, notes
    notes.append("archive has no single top-level folder; tree used as-is")
    return raw, notes


def blob_sha(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def content_sig(files, crlf_norm=False):
    out = {}
    for p, (_, d) in files.items():
        out[p] = blob_sha(d.replace(b"\r\n", b"\n") if crlf_norm else d)
    return out


def compare_sigs(a, b):
    diff = sum(1 for p in a.keys() & b.keys() if a[p] != b[p])
    return diff + len(a.keys() ^ b.keys())


# ---------------------------------------------------------------- catalog

SKIP_RULES = [
    (r"^altpkg/", "altpkg: repackaged .tar.xz duplicates of releases"),
    (r"^files/", "files/: ports, partner material, press kit, utilities; not a release tree"),
    (r"^yasslEWS", "yasslEWS: embedded web server product, separate line"),
    (r"^cyassl-provider", "cyassl-provider: JCE provider product, separate line"),
    (r"^cyassl-threadx", "cyassl-threadx: unversioned port bundle"),
]


def classify_server(name):
    """Return (product, version, role) or (None, None, skip_reason)."""
    for pat, reason in SKIP_RULES:
        if re.search(pat, name):
            return None, None, reason
    base = os.path.basename(name)
    m = re.match(r"^(yassl-update|yassl|cyassl|taocrypt|wolfssl)[-_](.+?)\.(zip|tar\.gz)$", base)
    if not m:
        return None, None, "unrecognized name"
    prod, ver = m.group(1), norm_version(m.group(2))
    role = {"yassl-update": "partial-update", "taocrypt": "note-only",
            "wolfssl": "note-only"}.get(prod, "release")
    if prod == "yassl-update":
        prod = "yassl"
    return prod, ver, role


def load_tsv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def classify_date_row(date, quote):
    if "UPPER BOUND" in date or "UPPER BOUND" in quote:
        return "upper", "upper bound: " + quote.strip('"').replace("UPPER BOUND: ", "")[:120]
    if re.search(r"freecode|freshmeat|<published>", quote):
        return "announce", "freecode/freshmeat announcement (UTC)"
    if "README" in quote or re.search(r"Release( notes)?,? (version )?\S+ \(\d", quote):
        return "readme", "vendor README release-notes date"
    if "PACKAGING" in quote:
        return "packaging", "newest file mtime in archive (lower bound)"
    return "upper", "upper bound (later import/upload): " + quote[:120]


DATE_RANK = {"readme": 0, "announce": 1, "packaging": 2, "upper": 3}


def load_dates():
    by = collections.defaultdict(list)
    for r in load_tsv(os.path.join(LINEAGE_ROOT, "gaps/dates.tsv")):
        d = re.search(r"\d{4}-\d{2}-\d{2}", r["release_date"])
        if not d:
            continue
        kind, basis = classify_date_row(r["release_date"], r["evidence_quote"])
        by[(r["product"].lower(), norm_version(r["version"]))].append(
            (DATE_RANK[kind], d.group(0), kind, basis))
    return by


def pick_date(evid):
    """Best rank wins, within a rank the earliest date; a date later than
    an upper bound loses to the earliest upper bound."""
    if not evid:
        return None
    best = min(evid)
    uppers = sorted(e for e in evid if e[2] == "upper")
    if uppers and best[1] > uppers[0][1]:
        u = min(uppers, key=lambda e: e[1])
        return u[1], "upper", "%s (CONFLICT: %s says %s)" % (u[3], best[3], best[1])
    return best[1], best[2], best[3]


class Candidate:
    def __init__(self, kind, path, sha256, role, rel):
        self.kind, self.path, self.sha256, self.role, self.rel = kind, path, sha256, role, rel
        self._files = None

    def files(self):
        if self._files is None:
            if sha256_file(self.path) != self.sha256:
                die("sha256 mismatch for %s" % self.path)
            self._files = read_archive(self.path)
        return self._files


def build_catalog():
    cands = collections.defaultdict(list)
    skipped = []
    srv = os.path.join(LINEAGE_ROOT, "server")
    with open(os.path.join(srv, "inventory.tsv"), newline="") as f:
        inv = [dict(zip(("path", "size", "mtime", "sha256"), x))
               for x in csv.reader(f, delimiter="\t")]
    for r in inv:
        rel = r["path"][2:] if r["path"].startswith("./") else r["path"]
        prod, ver, role = classify_server(rel)
        full = os.path.join(srv, "files", rel)
        if prod is None:
            skipped.append((rel, r["sha256"], role))
            continue
        key = ("yassl-update" if role == "partial-update" else prod, ver)
        cands[key].append(Candidate("server", full, r["sha256"], role, rel))
    for r in load_tsv(os.path.join(LINEAGE_ROOT, "gaps/manifest.tsv")):
        key = (r["product"].lower(), norm_version(r["version"]))
        cands[key].append(Candidate("gaps", r["local_path"], r["sha256"], "release",
                                    os.path.relpath(r["local_path"], LINEAGE_ROOT)))
    mdir = os.path.join(LINEAGE_ROOT, "mysql/final")
    mysql_dates = {}
    for r in load_tsv(os.path.join(mdir, "manifest.tsv")):
        key = (r["product"].lower(), r["version"])
        cands[key].append(Candidate("mysql", os.path.join(mdir, r["local_path"]),
                                    r["sha256"], "release", "mysql/final/" + r["local_path"]))
        mysql_dates[key] = (r["commit_date"][:10], r["mysql_sha"], r["notes"])
    wb = os.path.join(LINEAGE_ROOT, "wayback")
    if os.path.exists(os.path.join(wb, "verify.tsv")):
        for r in load_tsv(os.path.join(wb, "verify.tsv")):
            if r["archive_ok"] != "yes":
                continue
            prod, ver, role = classify_server(r["filename"])
            if prod is None or role != "release":
                continue
            cands[(prod, ver)].append(Candidate("wayback", os.path.join(wb, r["local_path"]),
                                                r["sha256"], "crosscheck", "wayback/" + r["local_path"]))

    dates = load_dates()
    rows = []
    for key in sorted(cands, key=lambda k: (k[0], version_key(k[1]))):
        prod, ver = key
        cs = cands[key]
        primary = choose_primary(prod, cs)
        if primary is None:
            continue
        pfiles = primary.files()[0]
        psig, alts = content_sig(pfiles), []
        for c in cs:
            if c is primary:
                continue
            same = c.sha256 == primary.sha256
            if same:
                verdict = "identical(sha256)"
            else:
                n = compare_sigs(psig, content_sig(c.files()[0]))
                verdict = "identical(content)" if n == 0 else "differs(%d files)" % n
            alts.append("%s:%s=%s" % (c.kind, c.rel, verdict))
        d = pick_date(dates.get(("yassl" if prod == "yassl-update" else prod, ver), []))
        if d is None and primary.kind == "mysql":
            d = (mysql_dates[key][0], "upper", "upper bound: MySQL import commit %s" % mysql_dates[key][1][:10])
        if d is None:
            basis = "newest file mtime in archive (lower bound, no external evidence)"
            if key in mysql_dates:
                basis += "; MySQL import %s is an upper bound" % mysql_dates[key][0]
            d = (newest_mtime(primary.path), "packaging", basis)
        status = {"partial-update": "partial-update", "note-only": "note-only"}.get(primary.role, "release")
        notes = list(primary.files()[1])
        if primary.kind == "mysql":
            notes.append("MySQL-imported tree (may carry MySQL-local patches/layout); mysql " + mysql_dates[key][2])
        rows.append(dict(product=prod, version=ver, status=status, source_kind=primary.kind,
                         path=primary.rel, abspath=primary.path, sha256=primary.sha256,
                         release_date=d[0], date_kind=d[1], date_basis=d[2],
                         alternates="; ".join(alts), lineage="", notes="; ".join(notes), cand=primary))
    # versions with date evidence but no archive anywhere
    have = {(r["product"], r["version"]) for r in rows}
    for (prod, ver), ev in sorted(dates.items(), key=lambda kv: (kv[0][0], version_key(kv[0][1]))):
        if (prod, ver) in have:
            continue
        d = pick_date(ev)
        rows.append(dict(product=prod, version=ver, status="missing", source_kind="none", path="",
                         abspath="", sha256="", release_date=d[0], date_kind=d[1], date_basis=d[2],
                         alternates="", lineage="", notes="no archive found in any input", cand=None))
    for rel, sha, reason in skipped:
        rows.append(dict(product="-", version="-", status="skipped", source_kind="server", path=rel,
                         abspath="", sha256=sha, release_date="", date_kind="", date_basis="",
                         alternates="", lineage="", notes=reason, cand=None))
    return rows


def choose_primary(prod, cs):
    order = {"server": 0, "gaps": 1, "mysql": 2}
    usable = [c for c in cs if c.kind in order]
    if not usable:
        return None
    # .zip over .tar.gz: zips are the only format from yassl 1.0.3 on and
    # the more complete copy; the yassl-2.3.2 tarball adds AppleDouble junk.
    pref = [".zip", ".tar.gz"]

    def k(c):
        fmt = next((i for i, e in enumerate(pref) if c.path.endswith(e)), 9)
        # dash-named file over underscore duplicate (cyassl_0.2.0.zip, yassl_1.2.0.zip)
        return (order[c.kind], fmt, "_" in os.path.basename(c.path))
    return min(usable, key=k)


def newest_mtime(path):
    if path.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            return "%04d-%02d-%02d" % max(i.date_time for i in z.infolist())[:3]
    with tarfile.open(path) as t:
        ts = max(m.mtime for m in t.getmembers())
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d")


CATALOG_COLS = ["product", "version", "status", "source_kind", "path", "sha256",
                "release_date", "date_basis", "alternates", "lineage", "notes"]


def write_catalog(rows, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(CATALOG_COLS)
        for r in rows:
            w.writerow([r[c] for c in CATALOG_COLS])


# ---------------------------------------------------------------- release notes

VER_TOKEN = r"(?:rc\d+-)?\d+\.\d+(?:\.\d+)?(?:rc\d+|[a-z])?"
HDR = re.compile(r"(?:yaSSL|CyaSSL)\b.*\b(?:Release|version)\b.*?(" + VER_TOKEN + ")")


def release_notes(files, ver):
    """The README section whose header names this version, up to the next
    version header; None when the README has no such section."""
    entry = files.get("README")
    if entry is None:
        return None
    out, on = [], False
    for line in entry[1].decode("utf-8", "replace").replace("\r\n", "\n").split("\n"):
        m = HDR.search(line)
        if m:
            vers = {norm_version(v) for v in re.findall(VER_TOKEN, line)}
            if on:
                break
            on = ver in vers
            if on:
                out.append(line.strip().lstrip("*").strip())
                continue
        if on:
            out.append(line.rstrip())
            if len(out) > 60:
                out.append("[... truncated; see README]")
                break
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out) if out else None


# ---------------------------------------------------------------- CVS input

class Cvs:
    """A linear git export of a SourceForge CVS module (SWH vault git-bare)."""

    def __init__(self, path, ref):
        self.path, self.ref = path, ref
        self.commits = []  # dicts: sha, headers (raw lines), message, date, tree


def is_git_dir(p):
    """True only if p itself is a repo; rev-parse alone would also accept
    any directory inside an enclosing worktree (swh/ sits inside ~/TASKS)."""
    if not os.path.isdir(p):
        return False
    r = run(["git", "-C", p, "rev-parse", "--absolute-git-dir"], check=False)
    gd = os.path.realpath(r.stdout.decode().strip()) if r.returncode == 0 else None
    return gd in (os.path.realpath(p), os.path.realpath(os.path.join(p, ".git")))


def find_cvs(swh_dir, name):
    """<swh>/<name>, <swh>/<name>.git, or the single <swh>/<name>/*.git
    (SWH vault tarballs extract to swh:1:rev:<sha>.git)."""
    inner = glob.glob(os.path.join(glob.escape(os.path.join(swh_dir, name)), "*.git"))
    if len(inner) > 1:
        die("several CVS exports for %s: %s" % (name, inner))
    for p in [os.path.join(swh_dir, name), os.path.join(swh_dir, name + ".git")] + inner:
        if not is_git_dir(p):
            continue
        heads = git_out(p, "for-each-ref", "--format=%(refname)", "refs/heads").split()
        head = git(p, "symbolic-ref", "-q", "HEAD", check=False).stdout.decode().strip()
        ref = head if head in heads else (heads[0] if len(heads) == 1 else None)
        if ref is None:
            die("%s: cannot pick a branch among %s" % (p, heads))
        return Cvs(p, ref)
    return None


def load_cvs(cvs, name, log_tsv):
    """Read every commit of the export in place. Its commit objects are not
    fetched: the SWH exports lack identity emails, which fsck rejects."""
    revs = git_out(cvs.path, "rev-list", "--reverse", "--parents", cvs.ref).splitlines()
    for line in revs:
        parts = line.split()
        if len(parts) > 2:
            die("%s CVS export has a merge (%s); linear history expected" % (name, parts[0]))
        raw = git(cvs.path, "cat-file", "commit", parts[0]).stdout
        hdr, _, msg = raw.partition(b"\n\n")
        hdrs = hdr.split(b"\n")
        ctime = next(h for h in hdrs if h.startswith(b"committer ")).split()[-2]
        tree = []
        for ent in git(cvs.path, "ls-tree", "-r", "-z", parts[0]).stdout.split(b"\0"):
            if ent:
                meta, path = ent.split(b"\t", 1)
                mode, _, sha = meta.split()
                tree.append((mode.decode(), sha.decode(), path))
        cvs.commits.append(dict(
            sha=parts[0], headers=hdrs, message=msg, tree=tree,
            date=datetime.datetime.fromtimestamp(int(ctime), datetime.timezone.utc).strftime("%Y-%m-%d"),
            tree_sha=next(h for h in hdrs if h.startswith(b"tree ")).split()[1].decode()))
    expect = load_tsv(log_tsv)
    if expect and (expect[0]["rev"] != cvs.commits[0]["sha"] or expect[-1]["rev"] != cvs.commits[-1]["sha"]
                   or len(expect) != len(cvs.commits)):
        print("WARNING: %s CVS export (%d commits %s..%s) differs from %s (%d commits %s..%s)" % (
            name, len(cvs.commits), cvs.commits[0]["sha"][:10], cvs.commits[-1]["sha"][:10],
            log_tsv, len(expect), expect[0]["rev"][:10], expect[-1]["rev"][:10]))


class BlobReader:
    """Blob contents, and CRLF-normalized blob ids, from a repo."""

    def __init__(self, repo):
        self.p = subprocess.Popen(["git", "-C", repo, "cat-file", "--batch"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.cache = {}

    def raw(self, sha):
        self.p.stdin.write(sha.encode() + b"\n")
        self.p.stdin.flush()
        hdr = self.p.stdout.readline().split()
        if len(hdr) != 3:
            die("cat-file --batch: bad object %s" % sha)
        data = self.p.stdout.read(int(hdr[2]))
        self.p.stdout.read(1)
        return data

    def norm(self, sha):
        if sha not in self.cache:
            self.cache[sha] = blob_sha(self.raw(sha).replace(b"\r\n", b"\n"))
        return self.cache[sha]

    def close(self):
        self.p.stdin.close()
        if self.p.wait() != 0:
            die("git cat-file --batch failed")


def tree_vs_archive(tree, arch_norm, blobs):
    """(tracked files differing or absent in the archive, archive-only files)."""
    t = {p.decode("utf-8", "surrogateescape"): blobs.norm(sha) for mode, sha, p in tree if mode != "160000"}
    differ = sum(1 for p, s in t.items() if arch_norm.get(p) != s)
    return differ, len(arch_norm.keys() - t.keys())


def match_cvs(rel, cvs, blobs):
    """Pick the CVS commit dated on/before release+window minimizing
    differing tracked files; ties -> fewer archive-only files -> later."""
    limit = (datetime.date.fromisoformat(rel["release_date"])
             + datetime.timedelta(days=CVS_MATCH_WINDOW_DAYS)).isoformat()
    arch_norm = content_sig(rel["cand"].files()[0], crlf_norm=True)
    best = None
    for i, c in enumerate(cvs.commits):
        if c["date"] > limit:
            break
        d, extra = tree_vs_archive(c["tree"], arch_norm, blobs)
        key = (d, extra, -i)
        if best is None or key < best[0]:
            best = (key, i)
    if best is None:
        return None
    (d, extra, _), i = best
    return dict(index=i, differ=d, archive_only=extra)


# ---------------------------------------------------------------- fast-import

def epoch(day):
    return int(datetime.datetime.fromisoformat(day + "T12:00:00+00:00").timestamp())


def fi_path(p):
    if any(c in p for c in '"\\\n') or p.startswith('"'):
        p = '"' + p.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
    return p.encode("utf-8", "surrogateescape")


class Stream:
    def __init__(self, repo, marks_file):
        self.marks_file = marks_file
        self.p = subprocess.Popen(["git", "-C", repo, "fast-import", "--quiet", "--done",
                                   "--export-marks=" + marks_file], stdin=subprocess.PIPE)
        self.n = 0

    def w(self, b):
        self.p.stdin.write(b if isinstance(b, bytes) else b.encode())

    def data(self, payload):
        if isinstance(payload, str):
            payload = payload.encode()
        self.w(b"data %d\n" % len(payload))
        self.w(payload)
        self.w(b"\n")

    def commit(self, ref, ident_lines, message, parent, files):
        self.n += 1
        self.w("commit %s\nmark :%d\n" % (ref, self.n))
        for line in ident_lines:
            self.w(line + b"\n")
        self.data(message)
        if parent:
            self.w("from %s\n" % parent)
        self.w(b"deleteall\n")
        for p in sorted(files):
            mode, data = files[p]
            self.w(b"M %s inline %s\n" % (mode.encode(), fi_path(p)))
            self.data(data)
        self.w(b"\n")
        return ":%d" % self.n

    def tag(self, name, target, day, message):
        self.w("tag %s\nfrom %s\ntagger %s %d +0000\n" % (name, target, TAGGER, epoch(day)))
        self.data(message)

    def finish(self):
        self.w(b"done\n")
        self.p.stdin.close()
        if self.p.wait() != 0:
            die("git fast-import failed")
        marks = {}
        with open(self.marks_file) as f:
            for line in f:
                m, sha = line.split()
                marks[m] = sha
        return marks


# ---------------------------------------------------------------- lineage

PRODUCTS = {
    "yassl": dict(display="yaSSL", cvs=(YASSL_CVS_START, YASSL_CVS_END)),
    "cyassl": dict(display="CyaSSL", cvs=(CYASSL_CVS_START, CYASSL_CVS_END)),
}


def source_line(r):
    return "Source: %s %s sha256=%s" % (r["source_kind"], r["path"], r["sha256"])


def damaged(r):
    return [n.split(" entry ", 1)[1].split(" (")[0] for n in r["notes"].split("; ")
            if n.startswith("DAMAGED:")]


def commit_message(prod, r):
    disp = PRODUCTS[prod]["display"]
    files = r["cand"].files()[0]
    notes = release_notes(files, r["version"])
    lines = ["%s %s" % (disp, r["version"]), "",
             notes or "(no release notes for %s in the archive README)" % r["version"], "",
             source_line(r), "Date basis: %s" % r["date_basis"]]
    for d in damaged(r):
        lines.append("Omitted (damaged in source archive): %s" % d)
    if r["source_kind"] == "mysql":
        lines.append("Note: tree as imported into MySQL; may carry MySQL-local patches and layout")
    return "\n".join(lines) + "\n"


def tag_message(prod, r, kind, extra=()):
    lines = ["%s %s" % (PRODUCTS[prod]["display"], r["version"]), "",
             "Kind: %s" % kind, source_line(r),
             "Release date: %s (basis: %s)" % (r["release_date"], r["date_basis"])]
    for d in damaged(r):
        lines.append("Omitted (damaged in source archive): %s" % d)
    return "\n".join(lines + list(extra)) + "\n"


def author_lines(day):
    t = epoch(day)
    return [("author %s %d +0000" % (AUTHOR, t)).encode(),
            ("committer %s %d +0000" % (AUTHOR, t)).encode()]


CVS_USERS = {b"touska": b"Todd Ouska <todd@yassl.com>",
             b"chrisconlon": b"Chris Conlon <chris@wolfssl.com>"}


def map_identity(header):
    """'author touska 1426703662 +0000' (SWH export, no email) ->
    ('author Todd Ouska <todd@yassl.com> 1426703662 +0000', b'touska').
    Timestamp and zone are kept verbatim; lines with an email pass through."""
    kw, rest = header.split(b" ", 1)
    who, ts, tz = rest.rsplit(b" ", 2)
    if b"<" in who:
        return header, who.split(b" <")[0]
    ident = CVS_USERS.get(who, b"%s <%s@users.sourceforge.net>" % (who, who))
    return b"%s %s %s %s" % (kw, ident, ts, tz), who


def plan_product(prod, rows, cvs):
    rels = sorted((r for r in rows if r["product"] == prod and r["status"] == "release"),
                  key=lambda r: version_key(r["version"]))
    if prod == "cyassl":
        rels, later = ([r for r in rels if r["release_date"] < WOLFSSL_GIT_START],
                       [r for r in rels if r["release_date"] >= WOLFSSL_GIT_START])
    else:
        later = []
    start, end = PRODUCTS[prod]["cvs"]
    if cvs is None:
        return rels, [], [], later
    pre = [r for r in rels if r["release_date"] < start]
    during = [r for r in rels if start <= r["release_date"] <= end]
    post = [r for r in rels if r["release_date"] > end]
    if pre + during + post != rels:
        print("WARNING: %s version order and date order disagree around the CVS window" % prod)
    return pre, during, post, later


def import_cvs_objects(out_repo, cvs):
    """Copy the export's reachable trees and blobs, not its commits (they lack
    identity emails, which fsck rejects), into out_repo."""
    objs = git(cvs.path, "rev-list", "--objects", "--no-object-names", cvs.ref).stdout
    typed = git(cvs.path, "cat-file", "--batch-check=%(objectname) %(objecttype)", input=objs).stdout
    want = b"".join(l.split()[0] + b"\n" for l in typed.splitlines() if not l.endswith(b" commit"))
    pack = git(cvs.path, "pack-objects", "--stdout", "-q", input=want).stdout
    git(out_repo, "index-pack", "--stdin", input=pack)


def commit_cvs(out_repo, cvs, parent):
    """Recreate each CVS commit on its original tree via hash-object (not
    fast-import, which drops the empty directories CVS exports carry).
    Returns the new commit ids, oldest first."""
    new = []
    for c in cvs.commits:
        hdr, cvs_author = [b"tree " + c["tree_sha"].encode()], None
        if parent:
            hdr.append(b"parent " + parent.encode())
        for h in c["headers"]:
            if h.startswith((b"author ", b"committer ")):
                line, user = map_identity(h)
                hdr.append(line)
                if h.startswith(b"author "):
                    cvs_author = user
            elif h.startswith(b"encoding "):
                hdr.append(h)
        msg = c["message"].rstrip(b"\n") + b"\n\nCVS-author: %s\nSWH-rev: %s\n" % (
            cvs_author, c["sha"].encode())
        parent = git(out_repo, "hash-object", "-t", "commit", "-w", "--stdin",
                     input=b"\n".join(hdr) + b"\n\n" + msg).stdout.decode().strip()
        new.append(parent)
    return new


def snapshot(st, prod, r, base, ref):
    return st.commit(ref, author_lines(r["release_date"]), commit_message(prod, r), base,
                     files=r["cand"].files()[0])


def build(out_repo, rows, swh_dir, wolfssl):
    run(["git", "init", "-q", "-b", "main", out_repo])
    open(os.path.join(out_repo, ".git", "lineage-builder"), "w").write("built by build_lineage.py\n")
    gitdir = os.path.join(out_repo, ".git")
    cvs = {}
    for prod in PRODUCTS:
        c = find_cvs(swh_dir, prod)
        if c is not None:
            load_cvs(c, prod, os.path.join(LINEAGE_ROOT, "swh", "%s-log.tsv" % prod))
            print("%s: using CVS export %s (%d commits)" % (prod, c.path, len(c.commits)))
        else:
            print("%s: no CVS export under %s; release snapshots only" % (prod, swh_dir))
        cvs[prod] = c
    plans = {prod: plan_product(prod, rows, cvs[prod]) for prod in PRODUCTS}
    tags = []  # (name, target sha or phase-2 :mark, row, kind, extra)

    # phase 1: snapshots before the CVS window (all of them without CVS)
    st = Stream(out_repo, os.path.join(gitdir, "lineage-marks-1"))
    pre_tip = {}
    for prod in PRODUCTS:
        parent = None
        for r in plans[prod][0]:
            parent = snapshot(st, prod, r, parent, "refs/heads/" + prod)
            tags.append(("%s-%s" % (prod, r["version"]), parent, r, "snapshot", ()))
        pre_tip[prod] = parent
    marks = st.finish()
    tags = [(n, marks[t], r, k, e) for n, t, r, k, e in tags]
    pre_tip = {p: marks[t] if t else None for p, t in pre_tip.items()}

    # phase 2: CVS history on top, original trees
    cvs_shas, head = {}, dict(pre_tip)
    for prod, c in cvs.items():
        if c is None:
            continue
        import_cvs_objects(out_repo, c)
        cvs_shas[prod] = commit_cvs(out_repo, c, pre_tip[prod])
        for orig, sha in zip(c.commits, cvs_shas[prod]):
            if git_out(out_repo, "rev-parse", sha + "^{tree}") != orig["tree_sha"]:
                die("%s: rewritten CVS commit %s has a different tree" % (prod, orig["sha"]))
        head[prod] = cvs_shas[prod][-1]
        git(out_repo, "update-ref", "refs/heads/" + prod, head[prod])

    # phase 3: CVS-era tags and side commits, snapshots after CVS, all tags
    st = Stream(out_repo, os.path.join(gitdir, "lineage-marks-3"))
    for prod in PRODUCTS:
        _, during, post, _ = plans[prod]
        if during:
            blobs = BlobReader(cvs[prod].path)
            for r in during:
                m = match_cvs(r, cvs[prod], blobs)
                c, sha = cvs[prod].commits[m["index"]], cvs_shas[prod][m["index"]]
                info = ("CVS commit: rewritten from original SWH revision %s (%s)" % (c["sha"], c["date"]),
                        "CVS match: %d tracked files differ or are absent in the archive "
                        "(CRLF-normalized); %d archive files not tracked in CVS" % (m["differ"], m["archive_only"]),
                        "Rule: commit dated <= release+%dd minimizing differing tracked files; "
                        "close if <= %d" % (CVS_MATCH_WINDOW_DAYS, CVS_CLOSE_MAX_DIFF))
                close = m["differ"] <= CVS_CLOSE_MAX_DIFF
                r["_cvs"] = dict(m, sha=c["sha"], close=close)
                tags.append(("%s-%s" % (prod, r["version"]), sha, r, "cvs-match", info))
                if not close:
                    side = snapshot(st, prod, r, sha, "refs/lineage-side/%s-%s" % (prod, r["version"]))
                    tags.append(("%s-%s-archive" % (prod, r["version"]), side, r, "archive-side",
                                 ("Side commit: exact archive tree; parent is the best CVS match %s" % c["sha"],)))
            blobs.close()
        parent = head[prod]
        for r in post:
            parent = snapshot(st, prod, r, parent, "refs/heads/" + prod)
            tags.append(("%s-%s" % (prod, r["version"]), parent, r, "snapshot", ()))
        if parent is None:
            die("%s: nothing to commit" % prod)
    for name, target, r, kind, extra in tags:
        st.tag(name, target, r["release_date"], tag_message(r["product"], r, kind, extra))
    marks = st.finish()
    tags = [(n, marks.get(t, t), r, k, e) for n, t, r, k, e in tags]
    for ref in git_out(out_repo, "for-each-ref", "--format=%(refname)", "refs/lineage-side").split():
        git(out_repo, "update-ref", "-d", ref)

    # lineage column
    for name, sha, r, kind, extra in tags:
        txt = "%s %s %s" % (kind, name, sha[:12])
        if kind == "cvs-match":
            txt += " differ=%d archive_only=%d" % (r["_cvs"]["differ"], r["_cvs"]["archive_only"])
        r["lineage"] = (r["lineage"] + "; " if r["lineage"] else "") + txt

    # wolfSSL join
    git(out_repo, "fetch", "--no-tags", "-q", "--update-head-ok", wolfssl, "+refs/heads/master:refs/heads/main")
    roots = [s for s in git_out(out_repo, "rev-list", "--max-parents=0", "main").split()
             if s.startswith(WOLFSSL_ROOT_ABBREV)]
    if len(roots) != 1:
        die("wolfSSL master root %s not found" % WOLFSSL_ROOT_ABBREV)
    wroot = roots[0]
    cy_tip = git_out(out_repo, "rev-parse", "refs/heads/cyassl")
    git(out_repo, "replace", "--graft", wroot, cy_tip)
    wtags = set(git_out(wolfssl, "tag").split())
    blobs = BlobReader(out_repo)
    for r in plan_product("cyassl", rows, cvs["cyassl"])[3]:
        v = r["version"]
        cands = ["v" + v, "v" + re.sub(r"\.0(rc\d+)$", r"\1", v)]
        wt = next((c for c in cands if c in wtags), None)
        if wt is None:
            r["lineage"] = "not tagged: no matching wolfSSL tag (%s)" % "/".join(cands)
            continue
        sha = git_out(wolfssl, "rev-parse", wt + "^{commit}")
        if git(out_repo, "merge-base", "--is-ancestor", sha, "main", check=False).returncode != 0:
            r["lineage"] = "not tagged: wolfSSL %s (%s) not on master" % (wt, sha[:12])
            continue
        tree = []
        for ent in git(out_repo, "ls-tree", "-r", "-z", sha).stdout.split(b"\0"):
            if ent:
                meta, path = ent.split(b"\t", 1)
                mode, _, bsha = meta.split()
                tree.append((mode.decode(), bsha.decode(), path))
        d, extra = tree_vs_archive(tree, content_sig(r["cand"].files()[0], True), blobs)
        msg = tag_message("cyassl", r, "wolfssl-tag", (
            "wolfSSL git tag: %s -> %s" % (wt, sha),
            "Archive comparison: %d tracked files differ or are absent in the archive "
            "(CRLF-normalized); %d archive files not tracked in git" % (d, extra)))
        env = dict(os.environ, GIT_COMMITTER_NAME=TAGGER.split(" <")[0],
                   GIT_COMMITTER_EMAIL=TAGGER.split("<")[1].rstrip(">"),
                   GIT_COMMITTER_DATE="%d +0000" % epoch(r["release_date"]))
        git(out_repo, "tag", "-a", "-F", "-", "cyassl-" + v, sha, input=msg.encode(), env=env)
        r["lineage"] = "wolfssl-tag cyassl-%s -> %s %s differ=%d archive_only=%d" % (v, wt, sha[:12], d, extra)
    blobs.close()
    return dict(cvs=cvs, wroot=wroot, cy_tip=cy_tip)


# ---------------------------------------------------------------- notes branch

def lineage_md(rows, info):
    def ver_list(pred):
        return ", ".join("%s-%s" % (r["product"], r["version"]) for r in rows if pred(r)) or "(none)"
    cvs_state = "\n".join(
        "- %s: %s" % (p, ("CVS export %s, %d commits, rewritten onto the branch; identities "
                          "mapped (export has no emails), trailers CVS-author/SWH-rev give the "
                          "original user and commit id, trees are unchanged" % (c.path, len(c.commits)))
                      if c else "no CVS export present at build time; release snapshots only")
        for p, c in info["cvs"].items())
    weak = ver_list(lambda r: r["status"] == "release" and r["date_basis"]
                    and not r["date_basis"].startswith(("vendor README", "freecode")))
    return """# wolfssl-lineage

Reconstructed history of yaSSL (C++, 2004-2017), CyaSSL (C, 2006-2011) and
its continuation wolfSSL (git from 2011-02-05). Local reconstruction; not an
official wolfSSL repository.

## Branches and refs

- `yassl`: one commit per yaSSL release (and the yaSSL CVS history when present).
- `cyassl`: one commit per CyaSSL release before wolfSSL git started (and the
  CyaSSL CVS history when present).
- `main`: wolfSSL `master` fetched unchanged from a local wolfSSL clone.
- `notes`: this file plus `catalog.tsv`, on an orphan branch.
- `refs/replace/%(wroot)s`: graft making wolfSSL's root commit
  ("1.8.8 init") a child of the `cyassl` tip `%(cy_tip)s`. `git log main`
  therefore runs back through CyaSSL. Use `git --no-replace-objects log` to see
  wolfSSL's real history. Replace refs are not fetched or pushed by default; a
  clone needs `git fetch origin 'refs/replace/*:refs/replace/*'`.
- Tags `yassl-<ver>`, `cyassl-<ver>`: annotated. `Kind:` in each annotation says
  what the tag is: `snapshot` (tree == release archive), `cvs-match` (CVS commit
  best matching the archive, with diff counts), `archive-side` (exact archive
  tree kept beside a poorly matching CVS commit, tag suffix `-archive`),
  `wolfssl-tag` (wolfSSL commit carrying the matching wolfSSL `v<ver>` tag).

## CVS state at build time

%(cvs_state)s

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
%(author)s, date = release date at 12:00 UTC. Tagger is the builder identity.

Release date precedence (from gaps/dates.tsv): vendor README release-notes
date > earliest freecode/freshmeat announcement > newest file mtime in the
archive (lower bound) > earliest upper bound (distro import, SourceForge
upload, MySQL import). A date later than any upper bound is replaced by that
upper bound and marked CONFLICT. Dates not from README or freecode are weak.

CVS matching rule: for releases dated inside a CVS window, the CVS commit
dated on or before release_date + %(win)d days that minimizes the number of CVS-tracked
files absent from or different in the archive (CRLF-normalized); ties go to
fewer archive-only files, then the later commit. If more than %(close)d tracked files
differ, the exact archive tree is also committed as a side commit (parent: the
matched CVS commit) tagged `<product>-<ver>-archive`.

## Gaps and caveats

- Weak dates: %(weak)s
- Versions known from dates evidence but with no archive anywhere: %(missing)s
- yassl-1.8.0.zip as served (and as captured by Wayback in 2016) is damaged:
  a stray byte shifts local headers. All entries except `configure` were
  recovered with valid CRC-32; `configure` (generated by autoconf) is omitted.
- yassl-update-* tarballs are partial updates; cataloged, not committed.
- taocrypt standalone and wolfssl 3.x archives are cataloged only; wolfSSL git
  covers wolfssl 3.x.
- CyaSSL releases dated on/after %(gitstart)s are tagged on wolfSSL commits only
  where wolfSSL has a matching tag; see `lineage` column in catalog.tsv.

## Making the graft permanent

The graft is a replace ref, so wolfSSL commit ids are unchanged. To bake it in
(this rewrites every wolfSSL commit id):

    git filter-repo --proceed --force   # filter-repo >= 2.38; replace refs become real parents

or `git filter-branch -- --all`; afterwards the replace ref is redundant. Do
this only in a scratch clone.

## Rebuild

    python3 ~/TASKS/yassl-lineage/build/build_lineage.py <new-path>
    python3 ~/TASKS/yassl-lineage/build/verify_lineage.py <new-path>

The builder uses swh/yassl and swh/cyassl automatically when those bare git
repos exist.
""" % dict(wroot=info["wroot"], cy_tip=info["cy_tip"], cvs_state=cvs_state, author=AUTHOR,
           win=CVS_MATCH_WINDOW_DAYS, close=CVS_CLOSE_MAX_DIFF, weak=weak,
           missing=ver_list(lambda r: r["status"] == "missing"), gitstart=WOLFSSL_GIT_START)


def write_notes(out_repo, md, catalog_path):
    st = Stream(out_repo, os.path.join(out_repo, ".git", "lineage-notes-marks"))
    t = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    ident = ("%s %d +0000" % (TAGGER, t)).encode()
    st.commit("refs/heads/notes", [b"author " + ident, b"committer " + ident],
              "Lineage notes and source catalog\n", None,
              files={"LINEAGE.md": ("100644", md.encode()),
                     "catalog.tsv": ("100644", open(catalog_path, "rb").read())})
    st.finish()


# ---------------------------------------------------------------- main

def check_out_path(out, force):
    out = os.path.realpath(out)
    allowed = (os.path.realpath(BUILD_DIR) + os.sep, os.path.realpath(os.path.expanduser("~/GIT/wolfssl-lineage")))
    if not (out.startswith(allowed[0]) or out == allowed[1]):
        die("output must be under %s or be %s" % allowed)
    if os.path.lexists(out):
        if not force or os.path.realpath(force) != out:
            die("%s exists; refusing (use --force-rebuild %s to replace a builder-made repo)" % (out, out))
        if not os.path.exists(os.path.join(out, ".git", "lineage-builder")):
            die("%s exists but was not made by this builder; not deleting it" % out)
        print("--force-rebuild: deleting builder-made repo %s" % out)
        shutil.rmtree(out)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out_repo")
    ap.add_argument("--force-rebuild", metavar="PATH")
    ap.add_argument("--swh-dir", default=os.path.join(LINEAGE_ROOT, "swh"))
    ap.add_argument("--wolfssl", default=os.path.expanduser("~/GIT/wolfssl"))
    ap.add_argument("--catalog-only", action="store_true")
    a = ap.parse_args()

    rows = build_catalog()
    cat_path = os.path.join(LINEAGE_ROOT, "catalog.tsv")
    if a.catalog_only:
        write_catalog(rows, cat_path)
        print("catalog: %d rows -> %s" % (len(rows), cat_path))
        return
    out = check_out_path(a.out_repo, a.force_rebuild)
    info = build(out, rows, os.path.abspath(a.swh_dir), os.path.abspath(a.wolfssl))
    write_catalog(rows, cat_path)
    print("catalog: %d rows -> %s" % (len(rows), cat_path))
    write_notes(out, lineage_md(rows, info), cat_path)
    git(out, "reset", "-q", "--hard", "main")
    if git_out(out, "remote"):
        die("output repo unexpectedly has remotes")
    print("built %s: %d release tags; main=%s; graft %s -> %s" % (
        out, len(git_out(out, "tag", "-l").split()), git_out(out, "rev-parse", "main")[:12],
        info["wroot"][:12], info["cy_tip"][:12]))


if __name__ == "__main__":
    main()
