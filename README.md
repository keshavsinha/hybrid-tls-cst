# Combinatorial security testing of RFC 10024 hybrid key shares

Artifact for *Combinatorial Security Testing of Hybrid Post-Quantum Key Exchange in TLS 1.3*
(M. Verma and K. Sinha). It tests how TLS 1.3 servers validate the hybrid key shares
X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024.

## Requirements
Python 3.10+ and `pip install -r requirements.txt`. The client side needs no TLS library.

## Harness
| File | Purpose |
|---|---|
| `ca.py` | Greedy t-way covering-array generator and coverage checker |
| `hello.py` | ClientHello builder, share mutations, byte-level oracle (`share_is_valid`), and `probe`, which classifies the response and, when needed, runs the TLS 1.3 key schedule to see which share the server used |
| `run.py` | `python3 run.py <label> <host> <port> <t> [out.csv] [timeout_s]`; t = 2, 3, or 0 (exhaustive) |
| `analyze.py` | Verdict counts, masking analysis, simulated random baseline (`results/analysis.txt`) |
| `swapstats.py` | Swapped-half X25519MLKEM768 statistics (`results/swapstats.txt`) |
| `verify_tables.py` | Checks every number in the paper's tables against the CSVs: `python3 verify_tables.py paper.tex` |
| `baseline.py`, `single.py`, `seq.py`, `tally.py` | Random baseline, single probes, record capture, quick tallies |
| `start_servers.sh`, `run_all.sh` | Start the test servers and reproduce every run |

`cert.pem`/`key.pem` are a throwaway self-signed test certificate for loopback servers only.

## Test servers (`servers/`)
- `gosrv/` – Go 1.26.9 `crypto/tls` server; `gosrv_go124/` is the same code with a `go 1.24` directive in `go.mod`.
- `rustsrv/` – rustls 0.23.46 with every aws-lc-rs key-exchange group enabled.
- `wolfsrv/srv.c` – looping wolfSSL server (AddressSanitizer, SIGPIPE ignored).
- `s2nsrv/srv.c` – minimal blocking s2n-tls server used for the root-cause analysis.
- `botan_policy.txt` – Botan `tls_server` policy.
- `patches/` – IPv4 listener patches for `bssl server` and NSS `selfserv`, and the Go seeded fault.

OpenSSL, BoringSSL, Botan, NSS and s2n-tls use their stock tools. Library versions and
commits are in the paper (Table 4) and in the result file names.

| Port | Target | Port | Target |
|---|---|---|---|
| 9444 | OpenSSL 4.0.3 | 9450 | Botan f1d805c |
| 9445 | Go 1.26.9 | 9451 | wolfSSL master c76acb6 |
| 9446 | Go 1.26.9 seeded fault | 9452 | s2n-tls `s2nd` |
| 9447 | rustls 0.23.46 | 9453 | NSS `selfserv` (start manually) |
| 9448 | BoringSSL 6c69fa8 | 9454 | s2n-tls minimal server |
| 9449 | wolfSSL 5.9.4 | 9455 | Go, `go 1.24` directive |

## Results (`results/`)
`results_<library>_{t2,t3,exh}.csv` has one row per test: factor values, oracle decision
(`must_reject`, `reason`), observed `outcome`/`detail`, and `verdict`.
