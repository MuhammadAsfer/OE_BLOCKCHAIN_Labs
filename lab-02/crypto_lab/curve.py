"""secp256k1 arithmetic from scratch.  y^2 = x^3 + 7 (mod p).  Points: (x, y) or None (= O)."""

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
Point = tuple[int, int] | None


def inverse_mod(a: int, m: int = P) -> int:
    """a^-1 mod m via Fermat (m prime): a^(m-2). 'Division' in a field is this, never '/'."""
    a %= m
    if a == 0:
        raise ZeroDivisionError("0 has no inverse")
    return pow(a, m - 2, m)


def is_on_curve(pt: Point) -> bool:
    if pt is None:
        return True
    x, y = pt
    return (y * y - x * x * x - 7) % P == 0


def neg(pt: Point) -> Point:
    return None if pt is None else (pt[0], (-pt[1]) % P)


def add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:          # P + (-P) = O  (also covers y == 0 doubling)
        return None
    if p1 == p2:
        lam = 3 * x1 * x1 * inverse_mod(2 * y1) % P      # tangent slope, a = 0
    else:
        lam = (y2 - y1) * inverse_mod(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def double(pt: Point) -> Point:
    return add(pt, pt)


def scalar_mul(k: int, pt: Point = G) -> Point:
    """Double-and-Add, MSB first. Extra add only when the bit is 1 -> timing leak."""
    k %= N
    if k == 0 or pt is None:
        return None
    result = pt
    for bit in bin(k)[3:]:
        result = double(result)
        if bit == "1":
            result = add(result, pt)
    return result


def scalar_mul_ladder(k: int, pt: Point = G) -> Point:
    """Montgomery ladder: one add + one double per bit regardless of its value."""
    k %= N
    r0, r1 = None, pt
    for bit in bin(k)[2:]:
        if bit == "0":
            r1, r0 = add(r0, r1), double(r0)
        else:
            r0, r1 = add(r0, r1), double(r1)
    return r0


# ---------- SEC1 encoding ----------
def sqrt_mod_p(a: int) -> int | None:
    r = pow(a, (P + 1) // 4, P)                  # valid because P % 4 == 3
    return r if r * r % P == a % P else None


def point_to_bytes(pt: Point, compressed: bool = True) -> bytes:
    if pt is None:
        raise ValueError("cannot encode the point at infinity")
    x, y = pt
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def point_from_bytes(b: bytes) -> Point:
    if len(b) == 33 and b[0] in (2, 3):
        x = int.from_bytes(b[1:], "big")
        if x >= P:
            raise ValueError("x out of range")
        y = sqrt_mod_p(x ** 3 + 7)
        if y is None:
            raise ValueError("x does not correspond to a point on the curve")
        if (y & 1) != (b[0] & 1):               # pick the root with the requested parity
            y = P - y
        return (x, y)
    if len(b) == 65 and b[0] == 4:
        pt = (int.from_bytes(b[1:33], "big"), int.from_bytes(b[33:], "big"))
        if not is_on_curve(pt):
            raise ValueError("point not on curve")
        return pt
    raise ValueError("bad SEC1 encoding")
