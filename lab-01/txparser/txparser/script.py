"""Script disassembler, classifier, and address encoders (base58check, bech32/bech32m)."""
import hashlib

OPCODES = {0x00: "OP_0", 0x4C: "OP_PUSHDATA1", 0x4D: "OP_PUSHDATA2", 0x4E: "OP_PUSHDATA4",
           0x4F: "OP_1NEGATE", 0x6A: "OP_RETURN", 0x75: "OP_DROP", 0x76: "OP_DUP",
           0x87: "OP_EQUAL", 0x88: "OP_EQUALVERIFY", 0xA9: "OP_HASH160",
           0xAC: "OP_CHECKSIG", 0xAD: "OP_CHECKSIGVERIFY", 0xAE: "OP_CHECKMULTISIG",
           0xB1: "OP_CHECKLOCKTIMEVERIFY", 0xB2: "OP_CHECKSEQUENCEVERIFY"}
for _i in range(1, 17):
    OPCODES[0x50 + _i] = f"OP_{_i}"


def disassemble(script: bytes) -> str:
    out, i = [], 0
    while i < len(script):
        op = script[i]; i += 1
        if 1 <= op <= 0x4B:                       # push opcodes are LENGTHS, not opcodes
            out.append(script[i:i + op].hex()); i += op
        elif op in (0x4C, 0x4D, 0x4E):
            w = {0x4C: 1, 0x4D: 2, 0x4E: 4}[op]
            n = int.from_bytes(script[i:i + w], "little"); i += w
            out.append(script[i:i + n].hex()); i += n
        else:
            out.append(OPCODES.get(op, f"OP_UNKNOWN_{op:#04x}"))
    return " ".join(out)


def classify(spk: bytes) -> str:
    n = len(spk)
    if n == 25 and spk[:3] == b"\x76\xa9\x14" and spk[-2:] == b"\x88\xac":
        return "p2pkh"
    if n == 23 and spk[0] == 0xA9 and spk[1] == 0x14 and spk[-1] == 0x87:
        return "p2sh"
    if n == 22 and spk[:2] == b"\x00\x14":
        return "p2wpkh"
    if n == 34 and spk[:2] == b"\x00\x20":
        return "p2wsh"
    if n == 34 and spk[:2] == b"\x51\x20":
        return "p2tr"
    if n in (35, 67) and spk[0] == n - 2 and spk[-1] == 0xAC:
        return "p2pk"
    if n >= 1 and spk[0] == 0x6A:
        return "nulldata"
    return "nonstandard"


# ---------- base58check ----------
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check(version: bytes, payload: bytes) -> str:
    raw = version + payload
    raw += hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    n = int.from_bytes(raw, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = _B58[r] + s
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + s


# ---------- bech32 / bech32m (BIP-173 / BIP-350) ----------
_CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (b >> i) & 1 else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for v in data:
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def segwit_address(hrp: str, witver: int, program: bytes) -> str:
    const = 1 if witver == 0 else 0x2BC830A3        # bech32 vs bech32m
    data = [witver] + _convertbits(program, 8, 5)
    mod = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ const
    checksum = [(mod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CH[d] for d in data + checksum)


def script_to_address(spk: bytes, hrp: str = "bcrt") -> str | None:
    t = classify(spk)
    if t == "p2wpkh":
        return segwit_address(hrp, 0, spk[2:])
    if t == "p2wsh":
        return segwit_address(hrp, 0, spk[2:])
    if t == "p2tr":
        return segwit_address(hrp, 1, spk[2:])
    return None
