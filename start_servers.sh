#!/bin/bash
# Start every test server on its port (loopback only).
# Set SRC to the directory holding the library source trees and OSSL to the OpenSSL 4.0.3 install prefix.
C=$(cd "$(dirname "$0")" && pwd); S=${SRC:-$HOME/src}; OSSL=${OSSL:-$HOME/opt/ossl}
cd $C
LD_LIBRARY_PATH=$OSSL/lib64 nohup $OSSL/bin/openssl s_server -accept 127.0.0.1:9444 -cert cert.pem -key key.pem -tls1_3 -groups X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:X25519 -naccept 100000 -quiet > /tmp/ossl_srv.log 2>&1 &
(cd servers/gosrv && nohup ./gosrv126 -addr 127.0.0.1:9445 > /tmp/go126.log 2>&1 &)
(cd servers/gosrv && nohup ./gosrv126_fault -addr 127.0.0.1:9446 > /tmp/gofault.log 2>&1 &)
(cd servers/rustsrv && nohup ./target/release/rustsrv 127.0.0.1:9447 > /tmp/rust.log 2>&1 &)
nohup $S/bssl/build/bssl server -accept 9448 -key key.pem -cert cert.pem -min-version tls1.3 -curves X25519MLKEM768:X25519 -loop > /tmp/bssl_srv.log 2>&1 &
pgrep -f "wolfsrv 9449" >/dev/null || (cd servers/wolfsrv && nohup ./wolfsrv 9449 > /tmp/wolf_srv.log 2>&1 &)
pgrep -f "wolfsrv_master 9451" >/dev/null || (cd servers/wolfsrv && nohup ./wolfsrv_master 9451 > /tmp/wolfm_srv.log 2>&1 &)
pgrep -f "botan tls_server" >/dev/null || (cd $S/botan && LD_LIBRARY_PATH=$S/botan nohup ./botan tls_server $C/cert.pem $C/key.pem --port=9450 --policy=$C/botan_policy.txt > /tmp/botan_srv.log 2>&1 &)
pgrep -f "s2nd" >/dev/null || nohup $S/s2n/build/bin/s2nd --ciphers default_pq --cert cert.pem --key key.pem --parallelize 127.0.0.1 9452 > /tmp/s2n_srv.log 2>&1 &
sleep 2
