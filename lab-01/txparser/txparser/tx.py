"""Bitcoin transaction parser (legacy + SegWit). Strict: bad input raises ValueError."""
import hashlib
from dataclasses import dataclass, field

from .compactsize import encode_compact_size
from .reader import Reader
from .script import classify, disassemble, script_to_address


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


@dataclass
class TxIn:
    prev_txid: str          # display order (big-endian hex), as RPCs show it
    vout: int
    script_sig: bytes
    sequence: int

    @property
    def is_coinbase(self) -> bool:
        return set(self.prev_txid) == {"0"} and self.vout == 0xFFFFFFFF


@dataclass
class TxOut:
    value: int              # satoshis; keep integers, never floats
    script_pubkey: bytes

    @property
    def type(self) -> str:
        return classify(self.script_pubkey)

    @property
    def asm(self) -> str:
        return disassemble(self.script_pubkey)

    def address(self, hrp: str = "bcrt"):
        return script_to_address(self.script_pubkey, hrp)


@dataclass
class Transaction:
    version: int
    inputs: list[TxIn]
    outputs: list[TxOut]
    locktime: int
    witnesses: list[list[bytes]] = field(default_factory=list)
    segwit: bool = False

    # ---------- serialisation ----------
    def serialize(self, include_witness: bool = True) -> bytes:
        w = include_witness and self.segwit
        out = self.version.to_bytes(4, "little")
        if w:
            out += b"\x00\x01"
        out += encode_compact_size(len(self.inputs))
        for i in self.inputs:
            out += bytes.fromhex(i.prev_txid)[::-1] + i.vout.to_bytes(4, "little")
            out += encode_compact_size(len(i.script_sig)) + i.script_sig
            out += i.sequence.to_bytes(4, "little")
        out += encode_compact_size(len(self.outputs))
        for o in self.outputs:
            out += o.value.to_bytes(8, "little")
            out += encode_compact_size(len(o.script_pubkey)) + o.script_pubkey
        if w:
            for stack in self.witnesses:
                out += encode_compact_size(len(stack))
                for item in stack:
                    out += encode_compact_size(len(item)) + item
        return out + self.locktime.to_bytes(4, "little")

    # ---------- identifiers & sizes ----------
    @property
    def txid(self) -> str:
        return sha256d(self.serialize(False))[::-1].hex()      # legacy bytes, reversed

    @property
    def wtxid(self) -> str:
        return sha256d(self.serialize(True))[::-1].hex()

    @property
    def size(self) -> int:
        return len(self.serialize(True))

    @property
    def stripped_size(self) -> int:
        return len(self.serialize(False))

    @property
    def weight(self) -> int:
        return 3 * self.stripped_size + self.size

    @property
    def vsize(self) -> int:
        return -(-self.weight // 4)                            # ceil

    @property
    def total_output_sat(self) -> int:
        return sum(o.value for o in self.outputs)


def parse_transaction(raw) -> Transaction:
    if isinstance(raw, str):
        s = "".join(raw.split())
        if len(s) % 2:
            raise ValueError("odd number of hex digits")
        try:
            data = bytes.fromhex(s)
        except ValueError:
            raise ValueError("not valid hex") from None
    else:
        data = bytes(raw)
    r = Reader(data)
    version = r.u32()
    segwit = False
    if r.peek(2) == b"\x00\x01":        # marker + flag. A real tx can't have 0 inputs.
        r.read(2)
        segwit = True
    n_in = r.compact()
    inputs = []
    for _ in range(n_in):
        prev = r.read(32)[::-1].hex()   # stored little-endian -> reverse for display
        vout = r.u32()
        sig = r.read(r.compact())
        seq = r.u32()
        inputs.append(TxIn(prev, vout, sig, seq))
    outputs = []
    for _ in range(r.compact()):
        value = r.u64()
        outputs.append(TxOut(value, r.read(r.compact())))
    witnesses = []
    if segwit:
        for _ in range(n_in):
            witnesses.append([r.read(r.compact()) for _ in range(r.compact())])
    locktime = r.u32()
    if r.remaining():
        raise ValueError(f"trailing data: {r.remaining()} byte(s) after locktime")
    return Transaction(version, inputs, outputs, locktime, witnesses, segwit)
