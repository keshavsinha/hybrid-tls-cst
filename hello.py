"""Raw TLS 1.3 ClientHello builder for RFC 10024 hybrid groups, with
fault-injection knobs, a byte-level validity oracle, and a probe that
classifies the server's response. When the server answers with a
ServerHello and an encrypted flight, the probe runs the TLS 1.3 key
schedule with the client's private keys to learn WHICH share the server
actually used (the first share, a valid duplicate, or neither)."""
import os, socket, struct, hashlib, hmac
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from kyber_py.ml_kem import ML_KEM_768, ML_KEM_1024

GROUPS = {  # name: (codepoint, kem, k, ec curve, pq_first, ct_len)
    "X25519MLKEM768":     (0x11EC, ML_KEM_768, 3, "x25519", True, 1088),
    "SecP256r1MLKEM768":  (0x11EB, ML_KEM_768, 3, "p256", False, 1088),
    "SecP384r1MLKEM1024": (0x11ED, ML_KEM_1024, 4, "p384", False, 1568),
}
EC_LEN = {"x25519": 32, "p256": 65, "p384": 97}
X25519 = 0x001D
ALERTS = {10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
          47: "illegal_parameter", 50: "decode_error", 51: "decrypt_error",
          70: "protocol_version", 80: "internal_error", 109: "missing_extension",
          110: "unsupported_extension", 112: "unrecognized_name"}
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
SUITES = {0x1301: (hashlib.sha256, 16, AESGCM), 0x1302: (hashlib.sha384, 32, AESGCM),
          0x1303: (hashlib.sha256, 32, ChaCha20Poly1305)}


def u8(b): return bytes([len(b)]) + b
def u16(b): return struct.pack(">H", len(b)) + b
def u24(b): return struct.pack(">I", len(b))[1:] + b
def ext(t, body): return struct.pack(">H", t) + u16(body)


# ---------------------------------------------------------------- shares
def ec_share(curve, mut):
    """Return (public bytes, private key or None)."""
    if curve == "x25519":
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()
        if mut == "zero":      return bytes(32), None
        if mut == "bad_point": return b"\x01" + bytes(31), None    # low-order point u=1
        if mut == "truncate":  return pub[:-1], None
        return pub, priv
    c = ec.SECP256R1() if curve == "p256" else ec.SECP384R1()
    priv = ec.generate_private_key(c)
    pub = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    if mut == "zero":      return bytes(len(pub)), None
    if mut == "bad_point":                                         # off-curve: y+1
        n = (len(pub) - 1) // 2
        y = (int.from_bytes(pub[1 + n:], "big") + 1) % (1 << (8 * n))
        return pub[:1 + n] + y.to_bytes(n, "big"), None
    if mut == "truncate":  return pub[:-1], None
    return pub, priv


def set_coef(ek, idx, val):
    """Overwrite 12-bit coefficient number idx in ByteEncode12 data."""
    b = bytearray(ek); j = (idx // 2) * 3
    if idx % 2 == 0:
        b[j] = val & 0xFF; b[j + 1] = (b[j + 1] & 0xF0) | (val >> 8)
    else:
        b[j + 1] = (b[j + 1] & 0x0F) | ((val & 0x0F) << 4); b[j + 2] = val >> 4
    return bytes(b)


def pq_share(kem, k, mut):
    """Return (encapsulation key bytes, decapsulation key)."""
    ek, dk = kem.keygen()
    ncoef = 256 * k
    if mut == "coef_q_first":   return set_coef(ek, 0, 3329), dk
    if mut == "coef_q_last":    return set_coef(ek, ncoef - 1, 3329), dk
    if mut == "coef_4095_mid":  return set_coef(ek, ncoef // 2, 4095), dk
    if mut == "truncate":       return ek[:-1], dk
    if mut == "extend":         return ek + b"\x00", dk
    return ek, dk


def make_share(group, pq_mut, ec_mut, order):
    """Return (share bytes, keys) where keys can recompute the shared secret
    (keys['ec'] is None when the EC part was mutated)."""
    _, kem, k, curve, pq_first, _ = GROUPS[group]
    (pq, dk), (e, priv) = pq_share(kem, k, pq_mut), ec_share(curve, ec_mut)
    keys = {"group": group, "dk": dk, "ec": priv}
    if order == "swapped":
        pq_first = not pq_first
    return (pq + e if pq_first else e + pq), keys


def hybrid_share(group, pq_mut, ec_mut, order):
    return make_share(group, pq_mut, ec_mut, order)[0]


# ---------------------------------------------------------------- oracle
def share_is_valid(group, share):
    """Byte-level oracle: would a spec-conformant server accept this share?
    Split at the fixed RFC 10024 offsets and check each component."""
    _, kem, k, curve, pq_first, _ = GROUPS[group]
    ek_len, ec_len = 384 * k + 32, EC_LEN[curve]
    if len(share) != ek_len + ec_len:
        return False, "length"
    ek, e = (share[:ek_len], share[ek_len:]) if pq_first else (share[ec_len:], share[:ec_len])
    for i in range(256 * k):                       # FIPS 203 7.2 modulus check
        j = (i // 2) * 3
        c = (ek[j] | (ek[j+1] & 0x0F) << 8) if i % 2 == 0 else (ek[j+1] >> 4 | ek[j+2] << 4)
        if c >= 3329:
            return False, "mlkem_modulus"
    if curve == "x25519":                          # RFC 8446 7.4.2 all-zero check
        try:
            z = x25519.X25519PrivateKey.generate().exchange(x25519.X25519PublicKey.from_public_bytes(e))
        except Exception:
            return False, "x25519_low_order"
        return (z != bytes(32)), ("ok" if z != bytes(32) else "x25519_low_order")
    c = ec.SECP256R1() if curve == "p256" else ec.SECP384R1()
    if e[0] != 4:
        return False, "ec_not_uncompressed"
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(c, e)
    except Exception:
        return False, "ec_off_curve"
    return True, "ok"


# ---------------------------------------------------------------- ClientHello
def client_hello(row, share):
    """Return (records to send, ClientHello handshake message, duplicate keys or None)."""
    g = row["group"]; code = GROUPS[g][0]
    shares, dup_keys = [(code, share)], None
    if row["extra"] == "x25519_fallback":
        shares.append((X25519, ec_share("x25519", "none")[0]))
    elif row["extra"] == "duplicate_group":
        dshare, dup_keys = make_share(g, "none", "none", "correct")
        shares.append((code, dshare))
    sg = [code, X25519] if row["sg_order"] == "hybrid_first" else [X25519, code]
    # RFC 8446 4.2.8: KeyShareEntry values MUST appear in supported_groups order
    shares.sort(key=lambda cs: sg.index(cs[0]))
    exts = (ext(43, u8(b"\x03\x04"))
            + ext(10, u16(b"".join(struct.pack(">H", x) for x in sg)))
            + ext(13, u16(bytes.fromhex("0403080404010503080508060807")))
            + ext(51, u16(b"".join(struct.pack(">H", c) + u16(d) for c, d in shares))))
    body = (b"\x03\x03" + os.urandom(32) + u8(os.urandom(32))
            + u16(b"\x13\x01\x13\x02\x13\x03") + b"\x01\x00" + u16(exts))
    hs = b"\x01" + u24(body)
    parts = [hs[:len(hs) // 2], hs[len(hs) // 2:]] if row["split"] == "yes" else [hs]
    return b"".join(b"\x16\x03\x01" + u16(p) for p in parts), hs, dup_keys


# ---------------------------------------------------------------- key schedule
def _hkdf_extract(h, salt, ikm): return hmac.new(salt, ikm, h).digest()


def _hkdf_expand(h, prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), h).digest(); out += t; i += 1
    return out[:n]


def _expand_label(h, secret, label, ctx, n):
    full = b"tls13 " + label
    return _hkdf_expand(h, secret, struct.pack(">H", n) + u8(full) + u8(ctx), n)


def shared_secret(keys, server_share):
    """RFC 10024 shared secret for our key pair and the server's share, or None."""
    if keys is None or keys["ec"] is None:
        return None
    _, kem, _, curve, pq_first, ct_len = GROUPS[keys["group"]]
    ec_len = EC_LEN[curve]
    if len(server_share) != ct_len + ec_len:
        return None
    ct, e = (server_share[:ct_len], server_share[ct_len:]) if pq_first else \
            (server_share[ec_len:], server_share[:ec_len])
    try:
        ss_pq = kem.decaps(keys["dk"], ct)
        if curve == "x25519":
            ss_ec = keys["ec"].exchange(x25519.X25519PublicKey.from_public_bytes(e))
        else:
            c = ec.SECP256R1() if curve == "p256" else ec.SECP384R1()
            ss_ec = keys["ec"].exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(c, e))
    except Exception:
        return None
    return ss_pq + ss_ec if pq_first else ss_ec + ss_pq


def decrypts(keys, ch, sh, rec_hdr, rec_body):
    """True if the first encrypted record decrypts under handshake keys
    derived from `keys` (i.e. the server used that key share)."""
    suite, server_share = _sh_fields(sh)
    if suite not in SUITES:
        return False
    ss = shared_secret(keys, server_share)
    if ss is None:
        return False
    h, klen, aead = SUITES[suite]
    hl = h().digest_size
    early = _hkdf_extract(h, bytes(hl), bytes(hl))
    derived = _expand_label(h, early, b"derived", h(b"").digest(), hl)
    hs_secret = _hkdf_extract(h, derived, ss)
    shts = _expand_label(h, hs_secret, b"s hs traffic", h(ch + sh).digest(), hl)
    key, iv = _expand_label(h, shts, b"key", b"", klen), _expand_label(h, shts, b"iv", b"", 12)
    try:
        aead(key).decrypt(iv, rec_body, rec_hdr)          # sequence number 0
        return True
    except Exception:
        return False


def _sh_fields(sh):
    """Return (cipher suite, key_share bytes) from a ServerHello message."""
    p = 4 + 2 + 32
    p += 1 + sh[p]
    suite = struct.unpack(">H", sh[p:p + 2])[0]; p += 3
    end = p + 2 + struct.unpack(">H", sh[p:p + 2])[0]; p += 2
    share = b""
    while p < end:
        t, l = struct.unpack(">HH", sh[p:p + 4]); p += 4
        if t == 51:
            share = sh[p + 4:p + 4 + struct.unpack(">H", sh[p + 2:p + 4])[0]] if l > 2 else b""
            return suite, share
        p += l
    return suite, share


def _selected_group(sh):
    p = 4 + 2 + 32
    p += 1 + sh[p] + 2 + 1
    end = p + 2 + struct.unpack(">H", sh[p:p + 2])[0]; p += 2
    while p < end:
        t, l = struct.unpack(">HH", sh[p:p + 4]); p += 4
        if t == 51:
            return struct.unpack(">H", sh[p:p + 2])[0]
        p += l
    return None


# ---------------------------------------------------------------- probe
def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d: break
        buf += d
    return buf


def probe(host, port, row, share, keys=None, timeout=5.0, follow=2.0):
    """Send one ClientHello. Returns (outcome, detail):
    ALERT/<name> | CLOSE/fin | CLOSE/rst | TIMEOUT | HRR/<group> |
    SH/<group>+<after> where <after> is flight:first, flight:dup,
    flight:none (encrypted flight that neither of our key pairs decrypts),
    alert, close or stalled."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return "CONNECT_FAIL", str(e)
    try:
        recs, ch, dup_keys = client_hello(row, share)
        s.sendall(recs)
        try:
            hdr = _recv_exact(s, 5)
        except ConnectionResetError:
            return "CLOSE", "rst"
        if len(hdr) < 5:
            return "CLOSE", "fin"
        ctype, ln = hdr[0], struct.unpack(">H", hdr[3:5])[0]
        data = _recv_exact(s, ln)
        if ctype == 21:
            return "ALERT", ALERTS.get(data[1], str(data[1])) if len(data) > 1 else "?"
        if ctype != 22 or data[:1] != b"\x02":
            return "OTHER", f"type={ctype}"
        sh = data[:4 + int.from_bytes(data[1:4], "big")]
        sel = _selected_group(sh)
        name = {v[0]: k for k, v in GROUPS.items()}.get(sel, "X25519" if sel == X25519 else hex(sel or 0))
        if data[6:38] == HRR_RANDOM:
            return "HRR", name
        s.settimeout(follow)
        after = "stalled"
        try:
            for _ in range(4):
                h2 = _recv_exact(s, 5)
                if len(h2) < 5:
                    after = "close"; break
                body = _recv_exact(s, struct.unpack(">H", h2[3:5])[0])
                if h2[0] == 20:
                    continue                                   # middlebox CCS
                if h2[0] == 21:
                    after = "alert"; break
                if h2[0] == 23:
                    if keys is None and dup_keys is None:
                        after = "flight:unchecked"; break     # caller did not ask
                    used = "first" if decrypts(keys, ch, sh, h2, body) else \
                           "dup" if decrypts(dup_keys, ch, sh, h2, body) else "none"
                    after = "flight:" + used; break
        except (socket.timeout, OSError):
            pass
        return "SH", name + "+" + after
    except socket.timeout:
        return "TIMEOUT", ""
    except OSError as e:
        return "CLOSE", "rst" if isinstance(e, ConnectionResetError) else str(e)
    finally:
        s.close()
