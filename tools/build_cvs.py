#!/usr/bin/env python3
"""Rebuild one CVS module as git history whose file contents come from real CVS.

cvs-fast-export (cfe) supplies only changeset grouping (its -R revmap) and commit
metadata. Every file revision's bytes come from `cvs co -p -r REV`; every cfe
synthetic commit's tree (branch bases, mixed-state tags) comes from
`cvs export -r SYMBOL`. The trunk 1.1 fragments cfe splits a `cvs import` into are
squashed into one commit carrying the vendor (1.1.1.1) commit's metadata.

Usage: build_cvs.py MODULE [SUFFIX]
Environment (defaults: the yaSSL SourceForge zip next to this script): WORK (output
and cfe inputs), CVSROOT_DIR, RAW_BASE (directory holding the module's ,v masters).
Writes repo cvsgood-MODULE[SUFFIX] and map-MODULE[SUFFIX].tsv (cfe commit, built commit, kind).
"""
import os, re, subprocess, sys, tempfile

M = sys.argv[1]
HERE = os.path.dirname(os.path.abspath(__file__))
CVS = os.path.expanduser("~/GIT/cvs-local/root/usr/bin/cvs")
WORK = os.environ.get("WORK", HERE)
ROOT = os.environ.get("CVSROOT_DIR", os.path.join(HERE, "cvsroot"))
RAW = os.path.join(os.environ.get("RAW_BASE", os.path.join(HERE, "raw/yassl")), M)
CFE = os.path.join(WORK, f"conv2-{M}")
SUF = sys.argv[2] if len(sys.argv) > 2 else ""
OUT = os.path.join(WORK, f"cvsgood-{M}{SUF}")
TMP = tempfile.mkdtemp(prefix=f"build-{M}.", dir=WORK)


def run(*a, cwd=None, inp=None, env=None):
    r = subprocess.run(a, cwd=cwd, input=inp, env=env, capture_output=True)
    if r.returncode:
        sys.exit(f"FAILED {a}: {r.stderr.decode(errors='replace')}")
    return r.stdout


def git(repo, *a, inp=None, env=None):
    return run("git", "-C", repo, *a, inp=inp, env=env).decode().strip()


# RCS metadata per file: revision -> state, exec bit of the ,v master
rcs, syms, dead = {}, set(), {}
for dp, _, fs in os.walk(RAW):
    for f in fs:
        if f.endswith(",v"):
            p = os.path.join(dp, f)
            head = open(p, encoding="latin-1").read().split("\ndesc\n", 1)[0]
            syms |= set(re.findall(r"\n\t([A-Za-z][\w-]*):", head.split("\nlocks", 1)[0]))
            deltas = re.findall(r"\n([0-9.]+)\ndate\t([^;]*);\tauthor [^;]*;\tstate ([^;]*);", head)
            states = {rev: st for rev, _, st in deltas}
            rel = os.path.relpath(p, RAW)[:-2].replace("Attic/", "")
            rcs[rel] = (states, bool(os.stat(p).st_mode & 0o111))
            for rev, d, st in deltas:
                if st == "dead":   # RCS dates: YY.MM.DD... before 2000, YYYY.MM.DD... after
                    y, mo, dd, h, mi, s = (int(x) for x in d.split("."))
                    dead.setdefault(rel, []).append(
                        (rev, int(subprocess.run(["date", "-u", "-d", f"{y:04d}-{mo:02d}-{dd:02d} {h:02d}:{mi:02d}:{s:02d}", "+%s"],
                                                 capture_output=True, text=True, check=True).stdout)))

marks = dict(l.split() for l in open(os.path.join(WORK, f"marks-{M}.txt")))
revs_of = {}
for line in open(os.path.join(WORK, f"revmap-{M}.txt")):
    f, rev, mark = line.split()
    revs_of.setdefault(marks[mark], []).append((f, rev))
imports = {(f, "1.1") for f, (st, _) in rcs.items() if "1.1.1.1" in st}

run("git", "init", "-q", OUT)
blobs = {}


def blob(f, rev):
    if (f, rev) not in blobs:
        data = run(CVS, "-Q", "-d", ROOT, "co", "-p", "-r", rev, f"{M}/{f}", cwd=TMP)
        blobs[f, rev] = git(OUT, "hash-object", "-w", "--stdin", inp=data)
    return blobs[f, rev]


def write_tree(files):
    env = dict(os.environ, GIT_INDEX_FILE=os.path.join(TMP, "index"))
    if os.path.exists(env["GIT_INDEX_FILE"]):
        os.unlink(env["GIT_INDEX_FILE"])
    info = "".join(f"{m} {b}\t{p}\n" for p, (m, b) in sorted(files.items()))
    git(OUT, "update-index", "--index-info", inp=info.encode(), env=env)
    return git(OUT, "write-tree", env=env)


def export_tree(sym):
    """Tree of `cvs export -r sym`."""
    d = tempfile.mkdtemp(dir=TMP)
    run(CVS, "-Q", "-d", ROOT, "export", "-r", sym, "-d", "x", M, cwd=d)
    files, top = {}, os.path.join(d, "x")
    for dp, _, fs in os.walk(top):
        for f in fs:
            p = os.path.join(dp, f)
            files[os.path.relpath(p, top)] = ("100755" if os.stat(p).st_mode & 0o111 else "100644",
                                              git(OUT, "hash-object", "-w", p))
    return files


def commit(tree, parents, meta_from):
    fmt = "%an%x00%ae%x00%ad%x00%cn%x00%ce%x00%cd%x00%B"
    an, ae, ad, cn, ce, cd, msg = git(CFE, "show", "-s", "--date=raw", f"--format={fmt}", meta_from).split("\x00", 6)
    env = dict(os.environ, GIT_AUTHOR_NAME=an, GIT_AUTHOR_EMAIL=ae, GIT_AUTHOR_DATE=ad,
               GIT_COMMITTER_NAME=cn, GIT_COMMITTER_EMAIL=ce, GIT_COMMITTER_DATE=cd)
    return git(OUT, "commit-tree", tree, *sum((["-p", p] for p in parents), []), inp=(msg + "\n").encode(), env=env)


tags_at = {}
for line in git(CFE, "for-each-ref", "--format=%(refname:short) %(objectname) %(*objectname)", "refs/tags").splitlines():
    name, o, peeled = (line.split() + [""])[:3]
    tags_at.setdefault(peeled or o, []).append(name)

vendor_commit = git(CFE, "rev-parse", "start^{commit}")
order = git(CFE, "rev-list", "--topo-order", "--reverse", "--all").splitlines()
fragments = [c for c in order if revs_of.get(c) and set(revs_of[c]) <= imports]
trunk = git(CFE, "rev-list", "--reverse", "master").splitlines()
assert trunk[:len(fragments)] == fragments, "import fragments are not the leading trunk commits"

# 1. squash the import fragments into one root commit with the vendor commit's metadata
files = {}
for c in fragments:
    for f, rev in revs_of[c]:
        files[f] = ("100755" if rcs[f][1] else "100644", blob(f, rev))
squash = commit(write_tree(files), [], vendor_commit)
files_of, newof, log = {squash: files}, {}, []
for c in fragments + [vendor_commit]:
    newof[c] = squash
    log.append((c, squash, "import"))
vendor_tree = write_tree(export_tree("start"))
assert vendor_tree == git(OUT, "rev-parse", f"{squash}^{{tree}}"), "cvs export -r start != squashed import"

# 2. everything else in topological order
used_dead = set()
for c in order:
    if c in newof:
        continue
    parents = git(CFE, "log", "-1", "--format=%P", c).split()
    assert len(parents) <= 1, f"unexpected merge {c}"
    base = newof[parents[0]] if parents else None
    revs = revs_of.get(c)
    synthetic = git(CFE, "log", "-1", "--format=%an", c) == "cvs-fast-export"
    # deletions: the revmap omits dead revisions, so take cfe's deletes and require a
    # dead RCS revision of that file within cfe's 300 s changeset window
    gone = git(CFE, "diff-tree", "-r", "--no-renames", "--diff-filter=D", "--name-only", "--no-commit-id", c).split() \
        if parents and not synthetic else []
    if (revs or gone) and not synthetic:
        files = dict(files_of[base]) if base else {}
        for f, rev in revs or []:
            files[f] = ("100755" if rcs[f][1] else "100644", blob(f, rev))
        t = int(git(CFE, "log", "-1", "--format=%ct", c))
        for f in gone:
            hit = [r for r in dead.get(f, []) if abs(r[1] - t) <= 300 and (f, r[0]) not in used_dead]
            assert hit, f"cfe deletes {f} in {c} but RCS has no dead revision near {t}"
            used_dead.add((f, hit[0][0]))
            files.pop(f, None)
        kind = "changeset"
    else:
        assert c in tags_at, f"cfe synthetic commit {c} has no tag to take its tree from"
        files, kind = export_tree(tags_at[c][0]), "synthetic"
    tree = write_tree(files)
    if base and git(OUT, "rev-parse", f"{base}^{{tree}}") == tree:
        newof[c] = base
        log.append((c, base, kind + "=parent"))
        continue
    n = commit(tree, [base] if base else [], c)
    files_of[n], newof[c] = files, n
    log.append((c, n, kind))

# 3. refs: cfe's names, plus RCS branch symbols cfe emitted no ref for (no commits on them)
for line in git(CFE, "for-each-ref", "--format=%(refname) %(objectname) %(*objectname)", "refs/heads", "refs/tags").splitlines():
    ref, o, peeled = (line.split() + [""])[:3]
    git(OUT, "update-ref", ref, newof[peeled or o])
tree_to_commit = {}
for n in git(OUT, "rev-list", "--all").splitlines():
    tree_to_commit.setdefault(git(OUT, "rev-parse", f"{n}^{{tree}}"), n)
extra = []
for sym in sorted(syms):
    if git(OUT, "for-each-ref", f"refs/heads/{sym}", f"refs/tags/{sym}") or sym == "touska":
        continue
    t = write_tree(export_tree(sym))
    assert t in tree_to_commit, f"no built commit matches empty branch {sym}"
    git(OUT, "update-ref", f"refs/heads/{sym}", tree_to_commit[t])
    extra.append(sym)
git(OUT, "update-ref", "refs/heads/touska", squash)   # vendor branch: only 1.1.1.1 == import

with open(os.path.join(WORK, f"map-{M}{SUF}.tsv"), "x") as fh:
    fh.writelines(f"{c}\t{n}\t{k}\n" for c, n, k in log)
kinds = {}
for *_, k in log:
    kinds[k] = kinds.get(k, 0) + 1
unused = sorted((f, r) for f, rs in dead.items() for r, _ in rs if (f, r) not in used_dead)
print(M, kinds, "file revisions", len(blobs), "dead used", len(used_dead), "dead unused", len(unused),
      "empty branches", extra, "tmp", TMP)
for f, r in unused:
    print("  unused dead revision", f, r)
