"""Cross-check every number in the paper's results tables and key in-text counts
against the raw CSVs. usage: python3 verify_tables.py ../paper/paper.tex"""
import csv, collections, os, re, sys
DATA = os.environ.get("CST_DATA", "results")

tex = open(sys.argv[1]).read()
LIB = {"OpenSSL 4.0.3": "openssl-4.0.3", "Go 1.26.9": "go1.26.9",
       "BoringSSL 6c69fa8": "boringssl-6c69fa8", "rustls 0.23.46": "rustls-0.23.46",
       "Botan f1d805c": "botan-f1d805c", "NSS 5cd24fd": "nss-5cd24fd",
       "wolfSSL 5.9.4": "wolfssl-5.9.4", "wolfSSL master c76acb6": "wolfssl-master-c76acb6",
       "s2n-tls 0369861": "s2n-tls-0369861", "Go 1.26.9, seeded fault": "go1.26.9-seededfault"}
COLS = ["OK", "NO_ALERT", "NO_RESPONSE", "HRR_SAME_GROUP", "LATE_ABORT", "FAIL_OPEN",
        "DUP_ACCEPT", "CLIENT_PREF", "UNSUPPORTED"]
SET = {"3w": "t3", "all": "exh", "2w": "t2"}

def load(lib, s):
    return list(csv.DictReader(open(f"{DATA}/results_{LIB_ID(lib)}_{s}.csv")))
LIB_ID = lambda lib: LIB[lib]

errors = 0
def check(name, got, want):
    global errors
    ok = got == want
    errors += not ok
    print(("  ok  " if ok else "  MISMATCH ") + f"{name}: paper={want} data={got}")

# --- results table ---
body = tex.split(r"\label{tab:results}")[1].split(r"\botrule")[0].split(r"\colrule")[1]
cur = None
for line in body.strip().split("\\\\"):
    line = line.replace("[3pt]", "").strip()
    if not line:
        continue
    cells = [c.strip() for c in line.split("&")]
    if cells[0]:
        cur = cells[0]
    rows = load(cur, SET[cells[1]])
    c = collections.Counter(r["verdict"] for r in rows)
    want_total = 90 if cells[1] == "3w" else 1728
    check(f"{cur} {cells[1]} total", len(rows), want_total)
    for col, v in zip(COLS, cells[2:]):
        check(f"{cur} {cells[1]} {col}", c.get(col, 0), int(v.replace(",", "")) if v else 0)
    extra = set(c) - set(COLS)
    if extra:
        errors += 1; print("  MISMATCH unexpected verdicts", extra)

# --- 2-way numbers quoted in text ---
for lib, col, want in [("wolfSSL 5.9.4", "NO_ALERT", 10), ("s2n-tls 0369861", "HRR_SAME_GROUP", 12),
                       ("s2n-tls 0369861", "NO_RESPONSE", 5), ("s2n-tls 0369861", "LATE_ABORT", 1),
                       ("s2n-tls 0369861", "DUP_ACCEPT", 4), ("s2n-tls 0369861", "OK", 2),
                       ("Go 1.26.9, seeded fault", "FAIL_OPEN", 3)]:
    rows = load(lib, "t2")
    check(f"{lib} 2w {col}", sum(r["verdict"] == col for r in rows), want)

# --- validation-test counts (3-way) ---
for lib, nval, ninv in [("Go 1.26.9", 90, 86), ("Botan f1d805c", 90, 86), ("NSS 5cd24fd", 90, 86),
                        ("wolfSSL 5.9.4", 90, 86), ("s2n-tls 0369861", 90, 86),
                        ("OpenSSL 4.0.3", 81, 77), ("rustls 0.23.46", 52, 49),
                        ("BoringSSL 6c69fa8", 38, 36)]:
    rows = [r for r in load(lib, "t3") if r["verdict"] not in ("CLIENT_PREF", "UNSUPPORTED")]
    check(f"{lib} 3w validation tests", len(rows), nval)
    check(f"{lib} 3w invalid validation tests", sum(r["must_reject"] == "True" for r in rows), ninv)

# --- exhaustive invalid count, wolfSSL masking ---
ex = load("wolfSSL 5.9.4", "exh")
check("exhaustive invalid shares", sum(r["must_reject"] == "True" for r in ex), 1680)
t3 = load("wolfSSL 5.9.4", "t3")
for extra, (na, n) in {"none": (22, 33), "x25519_fallback": (17, 27), "duplicate_group": (0, 26)}.items():
    rr = [r for r in t3 if r["extra"] == extra and r["must_reject"] == "True"]
    check(f"wolfSSL 3w NO_ALERT extra={extra}",
          (sum(r["verdict"] == "NO_ALERT" for r in rr), len(rr)), (na, n))

# --- seeded-fault exhaustive rate ---
sf = load("Go 1.26.9, seeded fault", "exh")
fo = sum(r["verdict"] == "FAIL_OPEN" for r in sf)
check("seeded exhaustive FAIL_OPEN rate (4 dp)", round(fo / 1728, 4), 0.1539)
check("analytic random miss (24) %", round(100 * (1 - fo / 1728) ** 24, 1), 1.8)

# --- s2n duplicate decrypt confirmations ---
s3 = load("s2n-tls 0369861", "t3")
check("s2n 3w DUP_ACCEPT with flight=dup",
      sum(r["verdict"] == "DUP_ACCEPT" and "flight:dup" in r["detail"] for r in s3), 20)

# --- model size ---
check("model product", 3 * 6 * 4 * 2 * 3 * 2 * 2, 1728)
print("\nERRORS:", errors)
