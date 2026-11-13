"""Analysis for the paper: effective test counts, exhaustive ground truth,
masking of the seeded fault and of the wolfSSL 5.9.4 deviation, and a
simulated random-testing baseline built from the exhaustive results."""
import csv, collections, glob, os, random, statistics
DATA = os.environ.get("CST_DATA", "results")
import ca, run

LIBS = ["openssl-4.0.3", "go1.26.9", "boringssl-6c69fa8", "rustls-0.23.46", "botan-f1d805c",
        "nss-5cd24fd", "wolfssl-5.9.4", "wolfssl-master-c76acb6", "s2n-tls-0369861",
        "go1.26.9-seededfault"]
F = list(run.MODEL)


def load(lib, suf):
    return list(csv.DictReader(open(f"{DATA}/results_{lib}_{suf}.csv")))


def key(x):
    return tuple(x[f] for f in F)


print("== verdict counts (effective = not UNSUPPORTED/CLIENT_PREF; invalid = oracle says reject)")
for lib in LIBS:
    for suf in ("t2", "t3", "exh"):
        try:
            r = load(lib, suf)
        except FileNotFoundError:
            continue
        c = collections.Counter(x["verdict"] for x in r)
        eff = [x for x in r if x["verdict"] not in ("UNSUPPORTED", "CLIENT_PREF")]
        inv = sum(x["must_reject"] == "True" for x in eff)
        print(f"{lib:24} {suf:3} n={len(r):4} eff={len(eff):4} eff_invalid={inv:4} {dict(sorted(c.items()))}")

print("\n== seeded fault: FAIL_OPEN rate by factor value (exhaustive)")
ex = load("go1.26.9-seededfault", "exh")
p = sum(x["verdict"] == "FAIL_OPEN" for x in ex) / len(ex)
print(f"p = {p:.4f} ({sum(x['verdict']=='FAIL_OPEN' for x in ex)}/{len(ex)})")
for f in F:
    rates = {}
    for v in run.MODEL[f]:
        sub = [x for x in ex if x[f] == v]
        rates[v] = f"{sum(x['verdict']=='FAIL_OPEN' for x in sub)}/{len(sub)}"
    print(f"  {f:9} {rates}")
coef = [x for x in ex if x["pq_mut"].startswith("coef")]
cnt = collections.Counter((x["ec_mut"], x["order"], x["group"] == "X25519MLKEM768", x["verdict"] == "FAIL_OPEN") for x in coef)
print("  coefficient mutations: fail-open only when ec_mut=none and (order=correct or ... ):")
for k_, v in sorted(cnt.items()):
    print("   ", k_, v)

print("\n== simulated random baseline from the exhaustive lookup (seeded fault)")
fo = {key(x): x["verdict"] == "FAIL_OPEN" for x in ex}
rnd = random.Random(2026)
for n in (24, 90):
    misses, hits, covs2, covs3 = 0, [], [], []
    for i in range(10000):
        rows = [{f: rnd.choice(run.MODEL[f]) for f in F} for _ in range(n)]
        h = sum(fo[tuple(rw[f] for f in F)] for rw in rows)
        hits.append(h); misses += (h == 0)
        if i < 300:
            covs2.append(ca.coverage(run.MODEL, rows, 2)); covs3.append(ca.coverage(run.MODEL, rows, 3))
    print(f"  n={n}: miss rate {misses/10000:.4f} (analytic {(1-p)**n:.4f}); mean hits {statistics.mean(hits):.2f}; "
          f"2-way cov {statistics.mean(covs2):.3f}; 3-way cov {statistics.mean(covs3):.3f}")
for t in (2, 3):
    r = load("go1.26.9-seededfault", f"t{t}")
    print(f"  covering array t={t}: {sum(x['verdict']=='FAIL_OPEN' for x in r)}/{len(r)} fail-open")

print("\n== wolfSSL 5.9.4 (exhaustive): NO_ALERT by factor value, invalid shares only")
w = [x for x in load("wolfssl-5.9.4", "exh") if x["must_reject"] == "True"]
print(f"  invalid {len(w)}, NO_ALERT {sum(x['verdict']=='NO_ALERT' for x in w)}")
for f in ("ec_mut", "extra", "order", "group", "pq_mut"):
    print(f"  {f:7}", {v: f"{sum(x['verdict']=='NO_ALERT' for x in w if x[f]==v)}/{sum(1 for x in w if x[f]==v)}" for v in run.MODEL[f]})
print("  by reason:", collections.Counter((x["reason"], x["verdict"]) for x in w))

print("\n== s2n-tls (exhaustive)")
s = load("s2n-tls-0369861", "exh")
print("  ", collections.Counter((x["verdict"], x["reason"]) for x in s).most_common())
print("   DUP_ACCEPT detail:", collections.Counter(x["detail"] for x in s if x["verdict"] == "DUP_ACCEPT"))

print("\n== rustls: valid hybrid share with classical-first preference (exhaustive)")
r = [x for x in load("rustls-0.23.46", "exh") if x["must_reject"] == "False" and x["verdict"] != "UNSUPPORTED"]
print("  ", collections.Counter((x["sg_order"], x["extra"], x["outcome"], x["detail"].split('+')[0]) for x in r))

print("\n== CLOSE details")
for lib in LIBS:
    for suf in ("t3", "exh"):
        try:
            r = load(lib, suf)
        except FileNotFoundError:
            continue
        c = collections.Counter(x["detail"] for x in r if x["outcome"] == "CLOSE")
        if c: print(f"  {lib} {suf}: {dict(c)}")
