from .compactsize import read_compact_size


class Reader:
    """Cursor over bytes. Every read checks bounds, so truncated input raises."""

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read(self, n: int) -> bytes:
        if n < 0 or self.offset + n > len(self.data):
            raise ValueError(f"truncated: need {n} bytes at offset {self.offset}, "
                             f"only {len(self.data) - self.offset} left")
        out = self.data[self.offset:self.offset + n]
        self.offset += n
        return out

    def u32(self) -> int:
        return int.from_bytes(self.read(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.read(8), "little")

    def compact(self) -> int:
        v, self.offset = read_compact_size(self.data, self.offset)
        return v

    def peek(self, n: int = 1) -> bytes:
        return self.data[self.offset:self.offset + n]

    def remaining(self) -> int:
        return len(self.data) - self.offset
