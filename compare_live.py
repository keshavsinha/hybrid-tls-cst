"""Compare verdicts from this run's live tests with the recorded results in /data.
usage: python3 compare_live.py <recorded_dir> <live_dir> <label> [<label> ...]"""
import csv, sys, collections
import run

F = list(run.MODEL)


def chance(k):
    """Rows whose outcome can depend on the fresh random ML-KEM key of each test: for the NIST-curve
    groups, a truncated point followed by an extended ML-KEM key is read as a point whose last byte
    is the key's first byte, which lies on the curve with probability of roughly 1/150 to 1/256."""
    r = dict(zip(F, k))
    return (r["group"] != "X25519MLKEM768" and r["pq_mut"] == "extend"
            and r["ec_mut"] == "truncate" and r["order"] == "correct")
rec_dir, live_dir, labels = sys.argv[1], sys.argv[2], sys.argv[3:]
bad = 0
for lab in labels:
    for suf in ("t2", "t3", "exh"):
        load = lambda d: {tuple(r[f] for f in F): r["verdict"]
                          for r in csv.DictReader(open(f"{d}/results_{lab}_{suf}.csv"))}
        rec, live = load(rec_dir), load(live_dir)
        diff = [k for k in rec if live.get(k) != rec[k]]
        unexpected = [k for k in diff if not chance(k)]
        bad += len(unexpected) + (len(rec) != len(live))
        c = collections.Counter(live.values())
        print(f"{lab:22} {suf:3} tests={len(live):4} verdicts={dict(sorted(c.items()))} "
              f"differences={len(diff)} (chance-dependent {len(diff) - len(unexpected)})")
        for k in diff[:5]:
            print("   ", "chance" if chance(k) else "UNEXPECTED", dict(zip(F, k)), rec[k], "->", live.get(k))
print("\nUNEXPECTED DIFFERENCES:", bad)
