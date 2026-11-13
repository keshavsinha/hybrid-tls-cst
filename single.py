"""Single-factor confirmation probes. usage: python3 single.py <port>"""
import sys, hello
port = int(sys.argv[1])
base = dict(pq_mut='none', ec_mut='none', order='correct', extra='none', sg_order='hybrid_first', split='no')
cases = [('pq_mut', v) for v in ['none', 'coef_q_first', 'coef_q_last', 'coef_4095_mid', 'truncate', 'extend']] + \
        [('ec_mut', v) for v in ['zero', 'bad_point', 'truncate']] + [('order', 'swapped')]
for extra in ['none', 'x25519_fallback', 'duplicate_group']:
    for g in hello.GROUPS:
        for f, v in cases:
            r = dict(base, group=g, extra=extra, **{f: v})
            sh = hello.hybrid_share(g, r['pq_mut'], r['ec_mut'], r['order'])
            ok, why = hello.share_is_valid(g, sh)
            print(f"{extra:16} {g:19} {f}={v:14} valid={ok!s:5} {why:18} ->", *hello.probe('127.0.0.1', port, r, sh, timeout=3))
