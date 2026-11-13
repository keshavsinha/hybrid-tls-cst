"""Random baseline vs covering array: t-way coverage and seeded-fault detection."""
import random, sys, statistics as st
import ca, hello, run
port = int(sys.argv[1])
def rand_rows(n, seed):
    r = random.Random(seed); return [{k: r.choice(v) for k, v in run.MODEL.items()} for _ in range(n)]
def detect(rows):
    hits = 0
    for r in rows:
        sh = hello.hybrid_share(r["group"], r["pq_mut"], r["ec_mut"], r["order"])
        ok, _ = hello.share_is_valid(r["group"], sh)
        o, d = hello.probe("127.0.0.1", port, r, sh)
        hits += run.verdict(r, not ok, True, o, d) == "FAIL_OPEN"
    return hits
for t, n in ((2, 24), (3, 90)):
    cov2 = [ca.coverage(run.MODEL, rand_rows(n, s), 2) for s in range(10)]
    cov3 = [ca.coverage(run.MODEL, rand_rows(n, s), 3) for s in range(10)]
    det = [detect(rand_rows(n, s)) for s in range(10)]
    print(f"random n={n}: 2-way cov {st.mean(cov2):.3f}  3-way cov {st.mean(cov3):.3f}  "
          f"fail-open hits mean {st.mean(det):.1f} (min {min(det)}, max {max(det)})")
