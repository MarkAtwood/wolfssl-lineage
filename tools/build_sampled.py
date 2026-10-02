#!/usr/bin/env python3
"""Rebuild a CVS module's main line by sampling real CVS at each changeset time.

For repositories whose main line lives on the vendor branch (repeated `cvs import`
of snapshots; e.g. Crypto++ `src`), per-revision rebuilding is the wrong model.
Here each cvs-fast-export (cfe) master commit supplies only a time and metadata;
the tree is `cvs export -D <time>`, which applies CVS's own default-branch rules.
Runs of empty-message / import-message commits within 300 s that contain a vendor
import are one commit carrying the vendor import's metadata. Commits whose sampled
tree equals the previous one are dropped and reported. Tags and branches get the
tree of `cvs export -r SYMBOL`: a matching built commit if one exists, otherwise a
parentless commit (as cfe does for mixed-revision tags).

Usage: WORK=... CVSROOT_DIR=... build_sampled.py MODULE
Writes WORK/sampled-MODULE (repo) and WORK/sampled-MODULE.tsv (cfe commit -> built).
"""
import os, re, subprocess, sys, tempfile

M = sys.argv[1]
WORK, ROOT = os.environ["WORK"], os.environ["CVSROOT_DIR"]
CVS = os.path.expanduser("~/GIT/cvs-local/root/usr/bin/cvs")
CFE, OUT = os.path.join(WORK, f"conv2-{M}"), os.path.join(WORK, f"sampled-{M}")
TMP = tempfile.mkdtemp(prefix=f"sampled-{M}.", dir=WORK)
EMPTY = "*** empty log message ***"


def run(*a, cwd=None, inp=None, env=None):
    r = subprocess.run(a, cwd=cwd, input=inp, env=env, capture_output=True)
    if r.returncode:
        sys.exit(f"FAILED {a}: {r.stderr.decode(errors='replace')}")
    return r.stdout.decode().strip()


def git(repo, *a, inp=None, env=None):
    return run("git", "-C", repo, *a, inp=inp.encode() if inp else None, env=env)


def export_tree(*sel):
    d = tempfile.mkdtemp(dir=TMP)
    run(CVS, "-Q", "-d", ROOT, "export", *sel, "-d", "x", M, cwd=d)
    top, info = os.path.join(d, "x"), []
    for dp, _, fs in os.walk(top):
        for f in fs:
            p = os.path.join(dp, f)
            info.append(f"{'100755' if os.stat(p).st_mode & 0o111 else '100644'} "
                        f"{git(OUT, 'hash-object', '-w', p)}\t{os.path.relpath(p, top)}\n")
    env = dict(os.environ, GIT_INDEX_FILE=os.path.join(d, "index"))
    git(OUT, "update-index", "--index-info", inp="".join(sorted(info)), env=env)
    return git(OUT, "write-tree", env=env)


def utc(t):
    return run("date", "-u", "-d", f"@{t}", "+%Y-%m-%d %H:%M:%S UTC")


def commit(tree, parents, meta_from, msg=None):
    fmt = "%an%x00%ae%x00%ad%x00%cn%x00%ce%x00%cd%x00%B"
    an, ae, ad, cn, ce, cd, m = git(CFE, "show", "-s", "--date=raw", f"--format={fmt}", meta_from).split("\x00", 6)
    env = dict(os.environ, GIT_AUTHOR_NAME=an, GIT_AUTHOR_EMAIL=ae, GIT_AUTHOR_DATE=ad,
               GIT_COMMITTER_NAME=cn, GIT_COMMITTER_EMAIL=ce, GIT_COMMITTER_DATE=cd)
    return git(OUT, "commit-tree", tree, *sum((["-p", p] for p in parents), []), inp=(msg or m) + "\n", env=env)


run("git", "init", "-q", OUT)
info = [l.split("\x00") for l in git(CFE, "log", "--reverse", "--format=%H%x00%ct%x00%s", "master").splitlines()]
master = [(c, int(t), s) for c, t, s in info]
vendor = []   # (time, commit) of vendor-branch commits that carry a real import message
if git(CFE, "for-each-ref", "refs/heads/import-1.1.1"):
    for c, t, s in (l.split("\x00") for l in git(CFE, "log", "--format=%H%x00%ct%x00%s", "import-1.1.1").splitlines()):
        if s != EMPTY:
            vendor.append((int(t), c))
import_msgs = {git(CFE, "log", "-1", "--format=%s", c) for _, c in vendor}

# group master into units: import bursts, or single commits
units, i = [], 0
while i < len(master):
    j = i
    if master[i][2] in import_msgs | {EMPTY}:
        while j + 1 < len(master) and master[j + 1][2] in import_msgs | {EMPTY} and master[j + 1][1] - master[j][1] <= 300:
            j += 1
    lo, hi = master[i][1], master[j][1]
    v = [(t, c) for t, c in vendor if lo <= t <= hi + 300]
    if j > i or v:
        if v:
            units.append((master[i:j + 1], max(hi, v[-1][0]), v[-1][1]))
        else:
            units.extend(([m], m[1], m[0]) for m in master[i:j + 1])
    else:
        units.append(([master[i]], master[i][1], master[i][0]))
    i = j + 1

log, prev, by_tree = [], None, {}
for members, t, meta in units:
    tree = export_tree("-D", utc(t))
    if prev and git(OUT, "rev-parse", f"{prev}^{{tree}}") == tree:
        log += [(m[0], prev, "same-state") for m in members]
        continue
    prev = commit(tree, [prev] if prev else [], meta)
    by_tree.setdefault(tree, prev)
    kind = "import" if len(members) > 1 or meta != members[0][0] else "changeset"
    log += [(m[0], prev, kind) for m in members]
git(OUT, "update-ref", "refs/heads/master", prev)

for ref in git(CFE, "for-each-ref", "--format=%(refname)", "refs/tags", "refs/heads").splitlines():
    name = ref.split("/", 2)[2]
    if name in ("master", "import-1.1.1"):
        continue
    tree = export_tree("-r", name)
    tgt = by_tree.get(tree)
    if not tgt:
        cfe_c = git(CFE, "rev-parse", f"{ref}^{{commit}}")
        tgt = commit(tree, [], cfe_c, f"CVS {ref.split('/')[1][:-1]} {name} (mixed CVS revisions; tree from cvs export -r {name})")
    git(OUT, "update-ref", ref, tgt)
    log.append((ref, tgt, "ref" if tree in by_tree else "ref-synthetic"))
vsyms = set()   # vendor branch: cfe calls it import-1.1.1; CVS names it in the symbol table
for dp, _, fs in os.walk(os.path.join(ROOT, M)):
    for f in fs:
        if f.endswith(",v"):
            head = open(os.path.join(dp, f), encoding="latin-1").read().split("\nlocks", 1)[0]
            vsyms |= set(re.findall(r"\n\t([A-Za-z][\w-]*):1\.1\.1[;\n]", head))
for name in sorted(vsyms):
    tree = export_tree("-r", name)
    if tree not in by_tree:
        by_tree[tree] = commit(tree, [], vendor[-1][1], f"CVS vendor branch {name} (tree from cvs export -r {name})")
    git(OUT, "update-ref", f"refs/heads/{name}", by_tree[tree])
    log.append((f"refs/heads/{name}", by_tree[tree], "vendor-branch"))

with open(os.path.join(WORK, f"sampled-{M}.tsv"), "x") as fh:
    fh.writelines(f"{a}\t{b}\t{k}\n" for a, b, k in log)
kinds = {}
for *_, k in log:
    kinds[k] = kinds.get(k, 0) + 1
print(M, "units", len(units), kinds, "trunk commits", git(OUT, "rev-list", "--count", "master"))
