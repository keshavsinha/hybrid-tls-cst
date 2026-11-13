"""Regenerate the 2-way and 3-way covering arrays used in the paper and check their coverage."""
import itertools
import ca, run

total = len(list(itertools.product(*run.MODEL.values())))
print(f"model: {len(run.MODEL)} factors, exhaustive product = {total}")
for t in (2, 3):
    rows = ca.generate(run.MODEL, t=t, seed=7)
    cov = {s: ca.coverage(run.MODEL, rows, s) for s in (1, 2, 3)}
    print(f"{t}-way array: {len(rows)} tests; coverage 1-way {cov[1]:.3f}, 2-way {cov[2]:.3f}, 3-way {cov[3]:.3f}")
