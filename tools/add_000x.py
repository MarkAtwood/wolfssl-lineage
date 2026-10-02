#!/usr/bin/env python3
"""Add yaSSL 0.0.2 and 0.0.3 as source-only release commits from the update
archives, and graft them under yaSSL 0.2.0 (parents: 0.0.3, Crypto++ 5.1).
Trees are the archives' exact bytes; the archives store every file as 0777
(Windows-made tar), so modes are normalized to 100644. Writes objects, tags and
one replace ref into ~/GIT/wolfssl-lineage; bake separately."""
import hashlib, os, re, subprocess, tarfile

L = os.path.expanduser("~/GIT/wolfssl-lineage")
SRV = os.path.expanduser("~/TASKS/yassl-lineage/server/files")
REL = [("0.0.2", "2004-03-18", 1079611200), ("0.0.3", "2004-03-29", 1080561600)]


def git(*a, inp=None, env=None):
    r = subprocess.run(["git", "-C", L, *a], input=inp, env=env, capture_output=True)
    if r.returncode:
        raise SystemExit(f"git {a}: {r.stderr.decode()}")
    return r.stdout.decode().strip()


def notes(readme, ver):
    out, on = [], False
    for line in readme.decode("latin-1").replace("\r\n", "\n").split("\n"):
        m = re.search(r"(?i)yassl\b.*\b(?:release|version)\b.*?(\d+\.\d+\.\d+)", line)
        if m:
            if on:
                break
            on = m.group(1) == ver
        if on:
            out.append(line.rstrip())
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out)


parent = None
for ver, day, ts in REL:
    name = f"yassl-update-{ver}.tar.gz"
    raw = open(os.path.join(SRV, name), "rb").read()
    sha = hashlib.sha256(raw).hexdigest()
    info, readme = [], None
    with tarfile.open(os.path.join(SRV, name)) as tf:
        for m in tf.getmembers():
            if m.isfile():
                p = os.path.normpath(m.name)
                data = tf.extractfile(m).read()
                b = git("hash-object", "-w", "--stdin", inp=data)
                info.append(f"100644 {b}\t{p}\n")
                readme = data if p == "Readme.txt" else readme
    idx = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"index-{ver}")
    env = dict(os.environ, GIT_INDEX_FILE=idx)
    if os.path.exists(idx):
        raise SystemExit(f"{idx} exists")
    git("update-index", "--add", "--index-info", inp="".join(sorted(info)).encode(), env=env)
    tree = git("write-tree", env=env)
    src = f"Source: server {name} sha256={sha}"
    msg = (f"yaSSL {ver} (source files only)\n\n{notes(readme, ver)}\n\n{src}\n"
           f"Date basis: freecode/freshmeat announcement (UTC)\n"
           f"Contents: the release's update archive, which holds all of yaSSL's own\n"
           f"src/ and include/ files plus Readme.txt. The complete release also\n"
           f"bundled CryptoPP, CML and build scripts; no copy of it is known.\n")
    who = dict(os.environ, GIT_AUTHOR_NAME="Todd Ouska", GIT_AUTHOR_EMAIL="todd@yassl.com",
               GIT_AUTHOR_DATE=f"{ts} +0000", GIT_COMMITTER_NAME="Todd Ouska",
               GIT_COMMITTER_EMAIL="todd@yassl.com", GIT_COMMITTER_DATE=f"{ts} +0000")
    c = git("commit-tree", tree, *(["-p", parent] if parent else []), inp=msg.encode(), env=who)
    tagenv = dict(os.environ, GIT_COMMITTER_NAME="wolfssl-lineage builder",
                  GIT_COMMITTER_EMAIL="lineage@invalid", GIT_COMMITTER_DATE=f"{ts} +0000")
    git("tag", "-a", f"yassl-{ver}", c, "-F", "-", env=tagenv,
        inp=(f"yaSSL {ver}\n\nKind: source-only (update archive)\n{src}\n"
             f"Release date: {day} (basis: freecode/freshmeat announcement (UTC))\n").encode())
    print(ver, "commit", c[:12], "tree", tree[:12], "files", len(info))
    parent = c

v020 = git("rev-parse", "yassl-0.2.0^{commit}")
old = git("log", "-1", "--format=%P", v020).split()
assert old == [git("rev-parse", "cryptopp-5.1^{commit}")], old
git("replace", "--graft", v020, parent, *old)
print("graft yassl-0.2.0 <-", parent[:12], old[0][:12])
