"""Greedy t-way covering array generator (AETG-style) with constraint support,
plus a t-way coverage measurement function. No external dependencies."""
import itertools, random


def _tuples(model, t, valid):
    names = list(model)
    need = set()
    for cols in itertools.combinations(range(len(names)), t):
        for vals in itertools.product(*[range(len(model[names[c]])) for c in cols]):
            need.add((cols, vals))
    return names, need


def generate(model, t=2, valid=lambda row: True, seed=1, candidates=60):
    """model: dict name -> list of values. valid(row_dict) -> bool."""
    rnd = random.Random(seed)
    names, need = _tuples(model, t, valid)
    k = len(names)
    sizes = [len(model[n]) for n in names]

    def as_dict(r):
        return {names[i]: model[names[i]][r[i]] for i in range(k)}

    # drop t-tuples that no valid row can contain (constraint-infeasible)
    feasible = set()
    for cols, vals in need:
        for _ in range(400):
            r = [rnd.randrange(s) for s in sizes]
            for c, v in zip(cols, vals):
                r[c] = v
            if valid(as_dict(r)):
                feasible.add((cols, vals)); break
    need = feasible
    rows = []
    while need:
        best, best_gain = None, -1
        for _ in range(candidates):
            cols, vals = rnd.choice(tuple(need))
            r = [rnd.randrange(s) for s in sizes]
            for c, v in zip(cols, vals):
                r[c] = v
            # hill-climb free columns
            for i in rnd.sample(range(k), k):
                if i in cols:
                    continue
                bv, bg = r[i], -1
                for v in range(sizes[i]):
                    r[i] = v
                    if not valid(as_dict(r)):
                        continue
                    g = _gain(r, need, t)
                    if g > bg:
                        bv, bg = v, g
                r[i] = bv
            if not valid(as_dict(r)):
                continue
            g = _gain(r, need, t)
            if g > best_gain:
                best, best_gain = list(r), g
        if best is None or best_gain <= 0:
            break
        rows.append(best)
        need -= _covered(best, t)
    return [as_dict(r) for r in rows]


def _covered(r, t):
    return {(cols, tuple(r[c] for c in cols)) for cols in itertools.combinations(range(len(r)), t)}


def _gain(r, need, t):
    return len(_covered(r, t) & need)


def coverage(model, rows, t, valid=lambda row: True):
    """Fraction of feasible t-way value combinations covered by rows."""
    names = list(model)
    idx = [{v: i for i, v in enumerate(model[n])} for n in names]
    have = set()
    for row in rows:
        r = [idx[i][row[n]] for i, n in enumerate(names)]
        have |= _covered(r, t)
    _, need = _tuples(model, t, valid)
    return len(have & need) / len(need)
