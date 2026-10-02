# Compare every CVS commit in the surgery output against the SWH original at file level
# (path, mode, blob sha), keyed by committer timestamp + subject. Empty dirs are ignored
# because git fast-import cannot represent them.
import subprocess, sys
orig_repo, new_repo, new_ref = sys.argv[1:4]
def run(*a): return subprocess.run(a,capture_output=True,text=True,check=True).stdout
def walk(d,ref):
    out={}
    for sha in run("git","-C",d,"rev-list",ref).split():
        hdr,msg=run("git","-C",d,"cat-file","-p",sha).split("\n\n",1)
        h={l.split(" ",1)[0]:l.split(" ",1)[1] for l in hdr.splitlines() if not l.startswith("parent")}
        out[(h["committer"].split()[-2],msg.strip().split("\n")[0])]=sha
    return out
o=walk(orig_repo,"HEAD"); n=walk(new_repo,new_ref)
missing=[k for k in o if k not in n]; bad=[]
for k,sha in o.items():
    if k in n and run("git","-C",orig_repo,"ls-tree","-r",sha)!=run("git","-C",new_repo,"ls-tree","-r",n[k]): bad.append(k)
print(f"orig={len(o)} found={len(o)-len(missing)} file-level mismatches={len(bad)}")
for k in bad[:5]: print("  BAD",k)
sys.exit(1 if missing or bad else 0)
