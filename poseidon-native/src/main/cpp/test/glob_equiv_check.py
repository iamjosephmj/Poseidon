import ctypes, ctypes.util, sys
libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
FNM_CASEFOLD = 0x10
def m(pat,val): return libc.fnmatch(pat.encode(), val.encode(), FNM_CASEFOLD) == 0
fails=0
for line in open(sys.argv[1] if len(sys.argv)>1 else "poseidon-runtime/src/main/cpp/test/glob_vectors.txt"):
    line=line.strip()
    if not line or line.startswith("#"): continue
    pat,val,exp=line.split("|"); got=1 if m(pat,val) else 0
    if got!=int(exp): fails+=1; print(f"MISMATCH {pat} {val} exp={exp} got={got}")
    else: print(f"OK {pat} {val} -> {got}")
print("FAILS", fails); sys.exit(1 if fails else 0)
