"""ECDSA over secp256k1: RFC 6979 nonces, low-s, verify, public-key recovery, nonce-reuse attack."""
import hashlib
import hmac

from .curve import G, N, P, add, scalar_mul, inverse_mod, neg, sqrt_mod_p


def _bits2octets(z: int) -> bytes:
    return (z % N).to_bytes(32, "big")


def rfc6979_nonce(d: int, z: int) -> int:
    """Deterministic k = HMAC-DRBG(d, z) with SHA-256 (RFC 6979 section 3.2). z = the message hash as int."""
    x, h1 = d.to_bytes(32, "big"), _bits2octets(z)
    V, K = b"\x01" * 32, b"\x00" * 32
    K = hmac.new(K, V + b"\x00" + x + h1, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + x + h1, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = int.from_bytes(V, "big")
        if 1 <= k < N:
            return k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def sign(d: int, z: int, k: int | None = None) -> tuple[int, int, int]:
    """Return (r, s, recid) with low-s. Pass k only to demonstrate nonce reuse."""
    if not 1 <= d < N:
        raise ValueError("private key out of range")
    k = rfc6979_nonce(d, z) if k is None else k
    R = scalar_mul(k, G)
    r = R[0] % N
    s = inverse_mod(k, N) * (z + r * d) % N
    if r == 0 or s == 0:
        raise ValueError("bad nonce")
    recid = (R[1] & 1) | (2 if R[0] >= N else 0)
    if s > N // 2:                                # low-s: flipping s negates k -> flip recid parity
        s = N - s
        recid ^= 1
    return r, s, recid


def verify(Q, z: int, r: int, s: int, require_low_s: bool = False) -> bool:
    if not (1 <= r < N and 1 <= s < N):
        return False
    if require_low_s and s > N // 2:
        return False
    w = inverse_mod(s, N)
    X = add(scalar_mul(z * w % N, G), scalar_mul(r * w % N, Q))
    return X is not None and X[0] % N == r


def recover_public_key(z: int, r: int, s: int, recid: int):
    x = r + (N if recid & 2 else 0)
    if x >= P:
        raise ValueError("invalid recid")
    y = sqrt_mod_p(x ** 3 + 7)
    if y is None:
        raise ValueError("no point for this r")
    if (y & 1) != (recid & 1):
        y = P - y
    R = (x, y)
    rinv = inverse_mod(r, N)
    # Q = r^-1 (sR - zG)
    sR = scalar_mul(s, R)
    zG = neg(scalar_mul(z % N, G))
    return scalar_mul(rinv, add(sR, zG))


def recover_private_key_from_nonce_reuse(z1: int, r: int, s1: int, z2: int, s2: int, Q) -> int | None:
    """Same k, same r. Low-s may have flipped either s, so try all four sign combinations
    and keep the d whose d*G equals the known public key Q."""
    for a in (s1, N - s1):
        for b in (s2, N - s2):
            diff = (a - b) % N
            if diff == 0:
                continue
            k = (z1 - z2) * inverse_mod(diff, N) % N
            d = (a * k - z1) * inverse_mod(r, N) % N
            if d and scalar_mul(d, G) == Q:
                return d
    return None
