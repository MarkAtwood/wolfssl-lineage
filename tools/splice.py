#!/usr/bin/env python3
"""Swap wolfssl-lineage's SWH-derived CVS layer for the CVS-verified rebuild.

Expects refs/cvsbuild/<module>/{heads,tags}/* fetched from cvsgood-<module>-v2.
Every commit outside the old CVS first-parent chain whose parent is inside it is
regrafted onto the new trunk commit that was current at its committer time (the
rule anchors.py used). The new import commit is grafted onto the old one's parent,
and TomsFastMath onto the new "add optional fast math" commit. CVS tags/branches
become refs/tags/cvs/<module>/* and refs/heads/cvs/<module>/*.

Usage: splice.py [--apply]   (dry run prints the plan)
"""
import subprocess, sys

L = "/home/langwei/GIT/wolfssl-lineage"
APPLY = "--apply" in sys.argv
IMPORT_MSG = {"yassl": "yaSSL 1.2.2 cvs import", "cyassl": "cyassl 0.5.1 cvs import"}
CVS_END = {"yassl": 1426704000, "cyassl": None}   # yassl branch continues past CVS


def git(*a):
    r = subprocess.run(["git", "-C", L, *a], capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"FAILED git {a}: {r.stderr}")
    return r.stdout.strip()


def ts(c):
    return int(git("log", "-1", "--format=%ct", c))


def tree(c):
    return git("rev-parse", f"{c}^{{tree}}")


plan, refs = [], []
children = {}
for line in git("rev-list", "--all", "--parents").splitlines():
    c, *ps = line.split()
    for p in ps:
        children.setdefault(p, []).append(c)

for m in ("yassl", "cyassl"):
    first = next(l.split()[0] for l in git("log", m, "--format=%H %s").splitlines() if l.endswith(IMPORT_MSG[m]))
    tip = (next(l.split()[0] for l in git("log", m, "--first-parent", "--format=%H %ct").splitlines()
                if int(l.split()[1]) <= CVS_END[m]) if CVS_END[m] else git("rev-parse", m))
    old = git("rev-list", "--first-parent", tip, f"^{first}~1").split()
    oldset = set(old)
    new = git("rev-list", "--reverse", f"refs/cvsbuild/{m}/heads/master").split()
    new_ts = [(ts(c), c) for c in new]

    def anchor(t):
        return [c for tc, c in new_ts if tc <= t][-1]

    plan.append((new[0], [git("rev-parse", f"{first}^")], f"{m}: new import <- old import's parent"))
    for o in old:
        for x in children.get(o, []):
            if x in oldset:
                continue
            ps = git("log", "-1", "--format=%P", x).split()
            nps = [anchor(ts(x)) if p in oldset else p for p in ps]
            a = anchor(ts(x))
            same = tree(o) == tree(a)
            plan.append((x, nps, f"{m}: {git('log', '-1', '--format=%s', x)[:45]} | old anchor "
                                 f"{git('log', '-1', '--format=%s', o)[:30]} -> new {git('log', '-1', '--format=%s', a)[:30]}"
                                 f"{'' if same else ' [anchor tree differs]'}"))
        for line in git("for-each-ref", "--points-at", o, "--format=%(refname)").splitlines():
            if not line.startswith(("refs/cvsbuild/", "refs/remotes/")):
                refs.append((line, anchor(ts(o)), f"{m}: ref moved to new trunk"))

    # CVS refs; a mixed-state tag whose tree equals a release snapshot points at the snapshot
    release_by_tree = {}
    for t in git("tag", "-l", f"{m}-*").split():
        release_by_tree.setdefault(tree(f"{t}^{{commit}}"), git("rev-parse", f"{t}^{{commit}}"))
    for line in git("for-each-ref", "--format=%(refname) %(objectname)", f"refs/cvsbuild/{m}").splitlines():
        r, c = line.split()
        kind, name = r.split("/")[3], r.split("/")[4]
        if name in ("master", "import-1.1.1"):
            continue
        tgt = c
        if kind == "tags" and not git("log", "-1", "--format=%P", c) and tree(c) in release_by_tree:
            tgt = release_by_tree[tree(c)]
        refs.append((f"refs/{kind}/cvs/{m}/{name}", tgt,
                     f"{m}: CVS {kind[:-1]} {name}{' -> release snapshot' if tgt != c else ''}"))

    tfm = git("rev-parse", "tomsfastmath-0.10^{commit}")
    for c in new:
        if m == "cyassl" and git("log", "-1", "--format=%s", c) == "add optional fast math and alloc overrides":
            plan.append((c, git("log", "-1", "--format=%P", c).split() + [tfm], "cyassl: TomsFastMath graft"))

for c, ps, why in plan:
    print("GRAFT", c[:10], "<-", " ".join(p[:10] for p in ps), "|", why)
for r, c, why in refs:
    print("REF  ", r, "->", c[:10], "|", why)
if APPLY:
    for c, ps, _ in plan:
        git("replace", "--graft", c, *ps)
    for r, c, _ in refs:
        git("update-ref", r, c)
    print("applied", len(plan), "grafts,", len(refs), "refs")
