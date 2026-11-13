"""Record the full sequence of records a server sends after one ClientHello."""
import socket, struct, sys, time, hello
def seq(port, row, share, wait=30):
    s = socket.create_connection(("127.0.0.1", port), timeout=wait)
    s.sendall(hello.client_hello(row, share)); out = []; t0 = time.time()
    try:
        while True:
            hdr = hello._recv_exact(s, 5)
            if len(hdr) < 5: out.append(f"CLOSE@{time.time()-t0:.1f}s"); break
            n = struct.unpack(">H", hdr[3:5])[0]; d = hello._recv_exact(s, n)
            name = {20: "CCS", 21: "ALERT", 22: "HS", 23: "ENC"}.get(hdr[0], str(hdr[0]))
            if hdr[0] == 21: name += ":" + hello.ALERTS.get(d[1], str(d[1]))
            if hdr[0] == 22: name += ":" + {2: "SH"}.get(d[0], str(d[0]))
            out.append(f"{name}({n})")
    except socket.timeout:
        out.append(f"TIMEOUT@{wait}s")
    return out
if __name__ == "__main__":
    port = int(sys.argv[1])
    base = dict(order='correct', extra='none', sg_order='hybrid_first', split='no')
    for g, pm, em in [("X25519MLKEM768", "none", "none"), ("X25519MLKEM768", "none", "zero"),
                      ("X25519MLKEM768", "none", "bad_point"), ("X25519MLKEM768", "coef_q_first", "none"),
                      ("SecP256r1MLKEM768", "coef_q_first", "none"), ("SecP256r1MLKEM768", "none", "bad_point")]:
        r = dict(base, group=g, pq_mut=pm, ec_mut=em)
        print(g, pm, em, seq(port, r, hello.hybrid_share(g, pm, em, "correct"), wait=int(sys.argv[2]) if len(sys.argv) > 2 else 30))
