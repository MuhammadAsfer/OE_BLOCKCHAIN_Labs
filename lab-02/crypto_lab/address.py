from Crypto.Hash import keccak

from .curve import scalar_mul


def keccak256(data: bytes) -> bytes:
    """Keccak-256 (pre-NIST padding). NOT hashlib.sha3_256."""
    return keccak.new(digest_bits=256, data=data).digest()


def public_key_to_address(pub) -> str:
    """pub = (x, y). Hash the 64-byte x||y (no 04 prefix), keep the last 20 bytes."""
    raw = pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big")
    return "0x" + keccak256(raw)[12:].hex()


def to_checksum_address(addr: str) -> str:
    """EIP-55: hash the lowercase hex STRING; uppercase a letter if its hash nibble >= 8."""
    a = addr.lower().removeprefix("0x")
    h = keccak256(a.encode()).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c for i, c in enumerate(a))


def private_key_to_address(d: int) -> str:
    return to_checksum_address(public_key_to_address(scalar_mul(d)))
