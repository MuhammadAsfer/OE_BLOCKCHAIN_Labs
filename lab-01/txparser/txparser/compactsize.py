"""CompactSize (VarInt): Bitcoin's variable-length integer. Little-endian payload."""


def encode_compact_size(n: int) -> bytes:
    if n < 0 or n >= 1 << 64:
        raise ValueError("CompactSize out of range")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def read_compact_size(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Return (value, new_offset). Works from any start offset."""
    if offset >= len(data):
        raise ValueError("truncated: no CompactSize byte")
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    end = offset + 1 + width
    if end > len(data):
        raise ValueError("truncated CompactSize")
    return int.from_bytes(data[offset + 1:end], "little"), end
