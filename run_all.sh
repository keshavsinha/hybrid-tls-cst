#!/bin/bash
# Run the 2-way and 3-way sets and the exhaustive product against every target.
# Timeout per handshake: 5 s for the arrays, 1 s for the exhaustive s2n-tls run.
cd "$(dirname "$0")"; mkdir -p results
while read label port; do
  for t in 2 3 0; do
    tmo=5; [ "$t" = 0 ] && [ "$label" = s2n-tls-0369861 ] && tmo=1
    suf=t$t; [ "$t" = 0 ] && suf=exh
    python3 run.py "$label" 127.0.0.1 "$port" "$t" "results/results_${label}_${suf}.csv" "$tmo" > /dev/null
  done
  echo "done $label"
done <<'T'
openssl-4.0.3 9444
go1.26.9 9445
go1.26.9-seededfault 9446
rustls-0.23.46 9447
boringssl-6c69fa8 9448
wolfssl-5.9.4 9449
botan-f1d805c 9450
wolfssl-master-c76acb6 9451
nss-5cd24fd 9453
s2n-tls-0369861 9452
T
echo ALLDONE
