"""BIP-39 seed, BIP-32 derivation (private + public), BIP-44 paths, parent-key recovery."""
import hashlib
import hmac
from pathlib import Path

from .curve import G, N, point_from_bytes, point_to_bytes, scalar_mul, add

WORDS = Path(__file__).with_name("bip39_english.txt").read_text().split()
HARD = 2**31


def entropy_to_mnemonic(entropy: bytes) -> str:
    cs_bits = len(entropy) * 8 // 32
    bits = bin(int.from_bytes(entropy, "big"))[2:].zfill(len(entropy) * 8)
    bits += bin(hashlib.sha256(entropy).digest()[0])[2:].zfill(8)[:cs_bits]
    return " ".join(WORDS[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11))


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """PBKDF2-HMAC-SHA512, 2048 rounds; the passphrase lives in the SALT."""
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), ("mnemonic" + passphrase).encode(), 2048)


def master_key_from_seed(seed: bytes) -> tuple[int, bytes]:
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(I[:32], "big")
    if not 0 < k < N:
        raise ValueError("invalid master key")
    return k, I[32:]


def private_to_public(k: int):
    return scalar_mul(k, G)


def _tweak(parent_k: int | None, parent_pub, chain: bytes, index: int):
    if index >= HARD:
        if parent_k is None:
            raise ValueError("hardened derivation needs the parent PRIVATE key")
        data = b"\x00" + parent_k.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = point_to_bytes(parent_pub) + index.to_bytes(4, "big")
    I = hmac.new(chain, data, hashlib.sha512).digest()
    return int.from_bytes(I[:32], "big"), I[32:]


def derive_child(k: int, chain: bytes, index: int) -> tuple[int, bytes]:
    """CKDpriv."""
    il, cc = _tweak(k, private_to_public(k), chain, index)
    if il >= N:
        raise ValueError("invalid child")
    child = (il + k) % N
    if child == 0:
        raise ValueError("invalid child")
    return child, cc


def derive_child_public(pub, chain: bytes, index: int):
    """CKDpub: works from an xpub (public key + chain code). Normal indices only."""
    if index >= HARD:
        raise ValueError("cannot derive a hardened child from a public key")
    il, cc = _tweak(None, pub, chain, index)
    return add(scalar_mul(il, G), pub), cc


def parse_path(path: str) -> list[int]:
    parts = path.split("/")
    if parts[0] != "m":
        raise ValueError("path must start with m")
    out = []
    for p in parts[1:]:
        hard = p.endswith(("'", "h", "H"))
        n = int(p.rstrip("'hH"))
        if not 0 <= n < HARD:
            raise ValueError("index out of range")
        out.append(n + HARD if hard else n)
    return out


def derive_path(seed: bytes, path: str) -> tuple[int, bytes]:
    k, c = master_key_from_seed(seed)
    for i in parse_path(path):
        k, c = derive_child(k, c, i)
    return k, c


def recover_parent_private_key(child_k: int, parent_pub, parent_chain: bytes, index: int) -> int:
    """The xpub leak: for a NORMAL child, I_L depends only on public data, so
    parent_k = child_k - I_L. Refuses hardened indices (I_L needs the parent private key)."""
    if index >= HARD:
        raise ValueError("hardened child: I_L cannot be computed without the parent private key")
    il, _ = _tweak(None, parent_pub, parent_chain, index)
    return (child_k - il) % N
