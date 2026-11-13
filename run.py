"""Combinatorial security testing of RFC 10024 hybrid key shares.
usage: python3 run.py <label> <host> <port> <t> [out.csv] [timeout_s]
(t = 0 runs the exhaustive product)"""
import csv, itertools, sys, time
import ca, hello

MODEL = {
    "group":    list(hello.GROUPS),
    "pq_mut":   ["none", "coef_q_first", "coef_q_last", "coef_4095_mid", "truncate", "extend"],
    "ec_mut":   ["none", "zero", "bad_point", "truncate"],
    "order":    ["correct", "swapped"],
    "extra":    ["none", "x25519_fallback", "duplicate_group"],
    "sg_order": ["hybrid_first", "classical_first"],
    "split":    ["no", "yes"],
}


def verdict(r, bad, supported, outcome, detail):
    """bad: byte-level oracle says the first share is invalid (RFC 10024 4.2,
    FIPS 203 7.2, RFC 9846 4.3.8.2 / 7.4.2). supported: the valid control
    handshake for this group succeeded. Every label below is assigned from
    observed behaviour plus the oracle; nothing is inferred from mutation names."""
    if not supported:
        return "UNSUPPORTED"
    group, _, after = detail.partition("+")
    classical_first = r["sg_order"] == "classical_first"
    if outcome == "SH":
        if group != r["group"]:                  # server picked the classical group
            return "CLIENT_PREF" if classical_first else "FALLBACK"
        if not bad:
            return "OK" if after.startswith("flight") else "FALSE_REJECT"
        if after == "flight:dup":
            return "DUP_ACCEPT"                  # provably used the valid duplicate
        if after.startswith("flight"):
            return "FAIL_OPEN"                   # derived keys from the invalid share
        return "LATE_ABORT"                      # ServerHello, then no encrypted flight
    if outcome == "HRR":
        if group == r["group"]:
            return "HRR_SAME_GROUP" if bad else "ANOMALY"
        return "CLIENT_PREF" if classical_first else "HRR_DOWNGRADE"
    if outcome == "ALERT":
        if not bad:
            return "OK" if r["extra"] == "duplicate_group" else "FALSE_REJECT"
        return "OK" if detail == "illegal_parameter" else "WRONG_ALERT"
    if outcome == "CLOSE":
        return "NO_ALERT" if bad else "FALSE_REJECT"
    if outcome == "TIMEOUT":
        return "NO_RESPONSE" if bad else "FALSE_REJECT"
    return "ANOMALY"


def main():
    label, host, port, t = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    out = sys.argv[5] if len(sys.argv) > 5 else f"results_{label}_t{t}.csv"
    tmo = float(sys.argv[6]) if len(sys.argv) > 6 else 5.0
    if t == 0:                                    # exhaustive: every combination
        rows = [dict(zip(MODEL, v)) for v in itertools.product(*MODEL.values())]
        print(f"{label}: {len(rows)} tests (exhaustive)")
    else:
        rows = ca.generate(MODEL, t=t, seed=7)
        print(f"{label}: {len(rows)} tests, {t}-way coverage = {ca.coverage(MODEL, rows, t):.3f}")
    supported = {}
    for g in MODEL["group"]:                     # positive controls first
        ctl = dict(group=g, pq_mut="none", ec_mut="none", order="correct",
                   extra="none", sg_order="hybrid_first", split="no")
        sh, keys = hello.make_share(g, "none", "none", "correct")
        o, d = hello.probe(host, port, ctl, sh, keys)
        supported[g] = (o == "SH" and d == g + "+flight:first")
    print("supported:", supported)
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["impl", "id", *MODEL, "must_reject", "reason", "outcome", "detail", "verdict"])
        w.writeheader()
        for i, r in enumerate(rows):
            share, keys = hello.make_share(r["group"], r["pq_mut"], r["ec_mut"], r["order"])
            ok, why = hello.share_is_valid(r["group"], share)
            # run the key schedule only where it decides the verdict
            check = (not ok) or r["extra"] == "duplicate_group"
            o, d = hello.probe(host, port, r, share, keys if check else None, timeout=tmo)
            w.writerow(dict(impl=label, id=i, **r, must_reject=not ok, reason=why, outcome=o, detail=d,
                            verdict=verdict(r, not ok, supported[r["group"]], o, d)))
            time.sleep(0.02)
    print("written", out)


if __name__ == "__main__":
    main()
