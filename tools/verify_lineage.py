#!/usr/bin/env python3
"""Verify a repo made by build_lineage.py against the source archives.

Usage: verify_lineage.py REPO [--work DIR] [--wolfssl DIR]

Independent of the builder: source archives are located by the sha256 in
each tag annotation (hashing the input dirs here), extracted with the system
unzip/tar, and compared with `git archive <tag>`. Exit status 1 on failure.
"""
import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys

ROOT = os.path.expanduser("~/TASKS/yassl-lineage")
SOURCE_DIRS = ["server/files", "gaps", "mysql/final/snapshots"]


def run(args, **kw):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
    return p.returncode, p.stdout, p.stderr.decode(errors="replace")


def must(args, **kw):
    rc, out, err = run(args, **kw)
    if rc != 0:
        sys.exit("verify: command failed (%d): %s\n%s" % (rc, " ".join(args), err))
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def index_sources():
    idx = {}
    for d in SOURCE_DIRS:
        for dp, _, fs in os.walk(os.path.join(ROOT, d)):
            for f in fs:
                if f.endswith((".zip", ".tar.gz", ".tgz")):
                    p = os.path.join(dp, f)
                    idx.setdefault(sha256(p), p)
    return idx


def snapshot_dir(top):
    """rel path -> ('l', target) | ('f', sha1, executable)."""
    out = {}
    for dp, dirs, fs in os.walk(top):
        for name in fs + [d for d in dirs if os.path.islink(os.path.join(dp, d))]:
            p = os.path.join(dp, name)
            rel = os.path.relpath(p, top)
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("l", os.readlink(p))
            else:
                with open(p, "rb") as f:
                    out[rel] = ("f", hashlib.sha1(f.read()).hexdigest(), bool(st.st_mode & stat.S_IXUSR))
    return out


def strip_single_top(files):
    tops = {p.split(os.sep, 1)[0] for p in files}
    if len(tops) == 1 and all(os.sep in p for p in files):
        t = tops.pop() + os.sep
        return {p[len(t):]: v for p, v in files.items()}
    return files


def compare(src, gitf):
    only_src = sorted(src.keys() - gitf.keys())
    only_git = sorted(gitf.keys() - src.keys())
    content = mode = 0
    for p in src.keys() & gitf.keys():
        a, b = src[p], gitf[p]
        if a[:2] != b[:2]:
            content += 1
        elif a[0] == "f" and a[2] != b[2]:
            mode += 1
    return only_src, only_git, content, mode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--work")
    ap.add_argument("--wolfssl", default=os.path.expanduser("~/GIT/wolfssl"))
    a = ap.parse_args()
    repo = os.path.realpath(a.repo)
    work = os.path.realpath(a.work or os.path.join(ROOT, "build", "verify-" + os.path.basename(repo)))
    if os.path.exists(work):
        sys.exit("verify: work dir %s exists; pass a new --work" % work)
    os.makedirs(work)
    failures = []

    idx = index_sources()
    tags = must(["git", "-C", repo, "for-each-ref", "--format=%(refname:short) %(objecttype)", "refs/tags"]).decode().split("\n")
    tags = [t.split() for t in tags if t]
    report = open(os.path.join(work, "report.tsv"), "w")
    report.write("tag\tkind\tsource\tonly_in_archive\tonly_in_git\tcontent_differ\texec_bit_differ\tresult\n")
    counts = {}
    for name, otype in tags:
        if otype != "tag":
            failures.append("%s: lightweight tag" % name)
            continue
        ann = must(["git", "-C", repo, "cat-file", "tag", name]).decode(errors="replace")
        kind = re.search(r"^Kind: (\S+)", ann, re.M)
        sha = re.search(r"^Source: \S+ (\S+) sha256=([0-9a-f]{64})", ann, re.M)
        if not kind or not sha:
            failures.append("%s: annotation lacks Kind/Source" % name)
            continue
        kind = kind.group(1)
        omitted = set(re.findall(r"^Omitted \(damaged in source archive\): (.+)$", ann, re.M))
        arc = idx.get(sha.group(2))
        if arc is None:
            failures.append("%s: no input file with sha256 %s" % (name, sha.group(2)))
            continue
        d_src, d_git = os.path.join(work, name, "archive"), os.path.join(work, name, "git")
        os.makedirs(d_src)
        os.makedirs(d_git)
        if arc.endswith(".zip"):
            rc, _, err = run(["unzip", "-q", "-o", arc, "-d", d_src])
            if rc not in (0, 1) and not (rc == 2 and omitted):
                failures.append("%s: unzip rc=%d %s" % (name, rc, err.strip()[:200]))
                continue
        else:
            must(["tar", "-xf", arc, "-C", d_src])
        tar = subprocess.Popen(["git", "-C", repo, "archive", "--format=tar", name], stdout=subprocess.PIPE)
        must(["tar", "-xf", "-", "-C", d_git], stdin=tar.stdout)
        if tar.wait() != 0:
            failures.append("%s: git archive failed" % name)
            continue
        src = strip_single_top(snapshot_dir(d_src))
        only_src, only_git, content, mode = compare(src, snapshot_dir(d_git))
        exact_kinds = ("snapshot", "archive-side")
        if kind in exact_kinds:
            ok = set(only_src) <= omitted and not only_git and not content and not mode
            result = "IDENTICAL" if ok and not only_src else ("IDENTICAL-except-omitted-damaged:" + ",".join(only_src) if ok else "MISMATCH")
            if not ok:
                failures.append("%s: %s archive=%d git=%d content=%d mode=%d e.g. %s %s" % (
                    name, result, len(only_src), len(only_git), content, mode, only_src[:3], only_git[:3]))
        else:
            result = "REPORTED"
        counts[(kind, result.split(":")[0])] = counts.get((kind, result.split(":")[0]), 0) + 1
        report.write("%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\n" % (
            name, kind, os.path.relpath(arc, ROOT), len(only_src), len(only_git), content, mode, result))
    report.close()

    # repo-level checks
    rc, _, err = run(["git", "-C", repo, "fsck", "--full", "--strict"])
    fsck = "ok" if rc == 0 else "FAILED: " + err.strip()[:300]
    if rc != 0:
        failures.append("git fsck " + fsck)
    remotes = must(["git", "-C", repo, "remote"]).decode().split()
    if remotes:
        failures.append("repo has remotes: %s" % remotes)
    main_sha = must(["git", "-C", repo, "rev-parse", "main"]).decode().strip()
    wmaster = must(["git", "-C", a.wolfssl, "rev-parse", "master"]).decode().strip()
    if main_sha != wmaster:
        failures.append("main %s != wolfSSL master %s" % (main_sha, wmaster))
    reps = must(["git", "-C", repo, "for-each-ref", "--format=%(refname:strip=2) %(objectname)", "refs/replace"]).decode().split()
    cy_tip = must(["git", "-C", repo, "rev-parse", "cyassl"]).decode().strip()
    graft_ok = False
    if len(reps) == 2:
        parents = must(["git", "-C", repo, "cat-file", "commit", reps[1]]).decode().split("\n")
        graft_ok = [l for l in parents if l.startswith("parent ")] == ["parent " + cy_tip]
    if not graft_ok:
        failures.append("replace graft missing or not onto cyassl tip")
    n_with = int(must(["git", "-C", repo, "rev-list", "--count", "main"]).decode())
    n_without = int(must(["git", "--no-replace-objects", "-C", repo, "rev-list", "--count", "main"]).decode())
    n_cy = int(must(["git", "-C", repo, "rev-list", "--count", "cyassl"]).decode())
    if n_with != n_without + n_cy:
        failures.append("main history with graft (%d) != wolfSSL (%d) + cyassl (%d)" % (n_with, n_without, n_cy))
    untagged = []
    tagged = set(must(["git", "-C", repo, "for-each-ref", "--format=%(*objectname)", "refs/tags"]).decode().split())
    for br in ("yassl", "cyassl"):
        for c in must(["git", "-C", repo, "rev-list", br]).decode().split():
            if c not in tagged and "cvs import" not in must(["git", "-C", repo, "log", "-1", "--format=%s", c]).decode():
                untagged.append(c)
    # untagged commits are expected only for CVS history
    has_cvs = bool(must(["git", "-C", repo, "log", "--format=%H", "--grep=^SWH-rev: ", "yassl", "cyassl"]).strip())
    if untagged and not has_cvs:
        failures.append("%d snapshot commits on yassl/cyassl lack a tag" % len(untagged))

    print("work dir: %s (report.tsv)" % work)
    for k in sorted(counts):
        print("  %-14s %-34s %d" % (k[0], k[1], counts[k]))
    print("tags: %d   fsck: %s   remotes: %s" % (len(tags), fsck, remotes or "none"))
    print("main == wolfSSL master: %s   graft onto cyassl tip: %s" % (main_sha == wmaster, graft_ok))
    print("main commits: %d with graft = %d wolfSSL + %d cyassl" % (n_with, n_without, n_cy))
    if failures:
        print("FAILURES (%d):" % len(failures))
        for f in failures:
            print("  " + f)
        sys.exit(1)
    print("VERIFY PASSED")


if __name__ == "__main__":
    main()
