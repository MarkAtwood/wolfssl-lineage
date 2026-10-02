# For each product: CVS commit timestamps (parsed from raw headers, since author lines lack email),
# release commits whose date falls inside the CVS span, and the CVS commit each one should hang off.
import subprocess, sys
def git(d,*a): return subprocess.run(["git","-C",d,*a],check=True,capture_output=True,text=True).stdout
def cvs_commits(d):
    out=[]
    for sha in git(d,"rev-list","--reverse","HEAD").split():
        hdr=git(d,"cat-file","-p",sha).split("\n\n",1)[0]
        ts=int([l for l in hdr.splitlines() if l.startswith("committer ")][0].split()[-2])
        out.append((ts,sha))
    return out
for P in ("yassl","cyassl"):
    cvs=cvs_commits(f"swh-{P}.git"); lo,hi=cvs[0][0],cvs[-1][0]
    rows=[]
    for line in git(f"snapA-{P}.git","for-each-ref","--format=%(refname:short) %(*objectname) %(*committerdate:unix)","refs/tags").splitlines():
        tag,commit,ts=line.split(); ts=int(ts)
        if ts<lo: kind="pre"
        elif ts>hi: kind="post"
        else: kind="cvs-era"
        anchor=max((c for c in cvs if c[0]<=ts),default=None)
        rows.append((ts,tag,commit,kind,anchor[1] if anchor else "-"))
    rows.sort()
    with open(f"anchorsA-{P}.tsv","x") as f:
        f.write("release_ts\ttag\tcommit\tkind\tcvs_anchor\n")
        for r in rows: f.write("\t".join(map(str,r))+"\n")
    k=[r[3] for r in rows]
    print(P,"cvs",len(cvs),"pre",k.count("pre"),"cvs-era",k.count("cvs-era"),"post",k.count("post"),
          "| last pre:",[r[1] for r in rows if r[3]=="pre"][-1:],"first post:",[r[1] for r in rows if r[3]=="post"][:1])
