"""Tally verdicts per results file. usage: python3 tally.py <glob>"""
import csv, collections, glob, sys
for f in sorted(glob.glob(sys.argv[1])):
    r = list(csv.DictReader(open(f)))
    c = collections.Counter(x['verdict'] for x in r)
    print(f.replace('results_', '').replace('.csv', ''), len(r), dict(sorted(c.items())))
