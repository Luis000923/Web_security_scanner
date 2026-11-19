"""Grade every run on its full scan report (revision primary metric). Writes testbed/reanalysis/full_report_metrics.json."""
import sys,glob,collections,json
sys.path.insert(0,"tools"); import eval_oracle as o
gt=o.load_ground_truth("testbed/ground_truth.json")
key=lambda v:o._finding_key(v.get("url",""),v.get("parameter") or v.get("param"),v.get("type",""))
def rep(d):
    r=json.load(open([p for p in sorted(glob.glob(d+"/report/scan_*.json")) if "enriched" not in p][-1]))
    return r
out={}
for root in ("testbed/results","testbed/results_rep"):
  for d in sorted(glob.glob(root+"/budget*_*")):
    if "zap" in d: continue
    r=rep(d); V=r["vulnerabilities"]; R={key(v) for v in V}; m=o.evaluate(R,gt)
    name=d.split("/")[-1]; tag=("rep:" if "rep" in root else "")+name
    e=dict(raw=len(V),tuples=len(R),TP=len(m.tp),FP=len(m.fp),trap=len(m.fp_on_traps),P=m.precision,R=m.recall,F1=m.f1,
           fp_by_type=dict(collections.Counter(k[2] for k in m.fp)), tp_by_type=dict(collections.Counter(k[2] for k in m.tp)))
    if "aitriage" in name:
        blk=o.load_ai_triage([p for p in sorted(glob.glob(d+"/report/scan_*.json")) if "enriched" not in p][-1])
        dec=blk["decisions"]; dropped={key(x) for x in dec if x.get("dropped")}
        pre=R|dropped; mp=o.evaluate(pre,gt)
        e["pre"]=dict(tuples=len(pre),TP=len(mp.tp),FP=len(mp.fp),trap=len(mp.fp_on_traps),P=mp.precision,R=mp.recall)
        e["lost_tp"]=len(mp.tp-m.tp); e["removed_fp"]=len(mp.fp-m.fp); e["removed_fp_by_type"]=dict(collections.Counter(k[2] for k in mp.fp-m.fp))
        e["lost_tp_by_type"]=dict(collections.Counter(k[2] for k in mp.tp-m.tp))
    out[tag]=e
    print(tag, {k:(round(v,4) if isinstance(v,float) else v) for k,v in e.items() if k not in("fp_by_type","tp_by_type")})
# anatomy B20 baseline
d="testbed/results/budget20_baseline"; R={key(v) for v in rep(d)["vulnerabilities"]}; m=o.evaluate(R,gt)
vuln_ep={(k[0],k[1]) for k in gt.positives}; trap_ep={(k[0],k[1]) for k in gt.traps}
scored={"xss","sql_injection","path_traversal","command_injection","ldap_injection"}
cat=collections.Counter()
for k in m.fp:
    ep=(k[0],k[1])
    if k in gt.traps: c="trap_hit"
    elif k[2] not in scored: c="unscored_type:"+k[2]
    elif ep in vuln_ep: c="scored_on_vuln_ep_other_type"
    elif ep in trap_ep: c="scored_on_trap_ep_other_type"
    else: c="outside_targets"
    cat[c]+=1
print("ANATOMY B20", dict(cat)); print("FP by type B20", out["budget20_baseline"]["fp_by_type"])
# ZAP overlap
z=json.load(open("testbed/results/zap_baseline/zap_tuples.json"))
Z={tuple(t) for t in (z if isinstance(z,list) else z.get("tuples",z))} if not isinstance(z,dict) or "tuples" in z else None
print("zap tuples type", type(z).__name__, (list(z)[:3] if isinstance(z,dict) else z[:2]))
mz=o.evaluate(Z,gt) if Z else None
if mz: print("ZAP",len(Z),len(mz.tp),len(mz.fp),"common TP with WSS B20", len(mz.tp & m.tp), "onlyZAP",len(mz.tp-m.tp),"onlyWSS",len(m.tp-mz.tp))
# restricted to scored types
Rs={k for k in R if k[2] in scored}; ms=o.evaluate(Rs,gt); print("WSS B20 scored types", len(Rs), len(ms.tp), len(ms.fp), round(ms.precision,4))
json.dump(out,open("testbed/reanalysis/full_report_metrics.json","w"),indent=1)
