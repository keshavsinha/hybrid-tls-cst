"""Lesson 2: count out-of-range ML-KEM coefficients in swapped X25519MLKEM768 shares."""
import statistics, sys
import hello
N = int(sys.argv[1]) if len(sys.argv) > 1 else 1000


def bad_coefs(ek):
    n = 0
    for i in range(768):
        j = (i // 2) * 3
        c = (ek[j] | (ek[j+1] & 0x0F) << 8) if i % 2 == 0 else (ek[j+1] >> 4 | ek[j+2] << 4)
        n += c >= 3329
    return n


res, valid = [], 0
for _ in range(N):
    sh, _ = hello.make_share("X25519MLKEM768", "none", "none", "swapped")
    valid += hello.share_is_valid("X25519MLKEM768", sh)[0]
    res.append(bad_coefs(sh[:1184]))
q = statistics.quantiles(res, n=20)
print(f"trials {N}, valid {valid}, mean {statistics.mean(res):.1f}, "
      f"5th pct {q[0]:.0f}, 95th pct {q[-1]:.0f}, min {min(res)}, max {max(res)}")
