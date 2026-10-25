"""Ledger state + block tree. Consensus engines (pow.py, pos.py) feed it; it does not care which."""
import hashlib
import json
from dataclasses import dataclass, field

COINBASE = "coinbase"
REWARD = 50
GENESIS_PARENT = "0" * 64


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


@dataclass(frozen=True)
class Tx:
    sender: str
    recipient: str
    amount: int
    nonce: int                       # sequential per sender: replay protection

    @property
    def txid(self) -> str:
        return hashlib.sha256(json.dumps([self.sender, self.recipient, self.amount, self.nonce]).encode()).hexdigest()


class InvalidBlock(Exception):
    pass


class State:
    """Account model: balances plus sequential nonces."""

    def __init__(self, balances=None, nonces=None):
        self.balances = dict(balances or {})
        self.nonces = dict(nonces or {})

    def copy(self):
        return State(self.balances, self.nonces)

    def apply(self, tx: Tx):
        if tx.amount <= 0:
            raise InvalidBlock("amount must be positive")
        if tx.nonce != self.nonces.get(tx.sender, 0):
            raise InvalidBlock(f"bad nonce {tx.nonce}, expected {self.nonces.get(tx.sender, 0)}")
        if self.balances.get(tx.sender, 0) < tx.amount:
            raise InvalidBlock("insufficient balance")
        self.balances[tx.sender] -= tx.amount
        self.balances[tx.recipient] = self.balances.get(tx.recipient, 0) + tx.amount
        self.nonces[tx.sender] = tx.nonce + 1


def merkle_root(txids: list[str]) -> str:
    if not txids:
        return "0" * 64
    level = [bytes.fromhex(t) for t in txids]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])                  # odd count: last pairs with itself
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()


def header_prefix(height, parent, merkle, timestamp, difficulty, miner="m") -> bytes:
    # the miner (coinbase recipient) is committed to by the header, as in Bitcoin
    return f"{height}|{parent}|{merkle}|{timestamp}|{difficulty}|{miner}|".encode()


@dataclass(frozen=True)
class Block:
    height: int
    parent: str
    txs: tuple
    miner: str = "m"
    difficulty: int = 1
    nonce: int = 0
    timestamp: int = 0

    @property
    def merkle(self) -> str:
        return merkle_root([t.txid for t in self.txs])

    @property
    def header(self) -> bytes:
        return header_prefix(self.height, self.parent, self.merkle, self.timestamp, self.difficulty, self.miner) + str(self.nonce).encode()

    @property
    def digest(self) -> bytes:
        return sha256d(self.header)

    @property
    def hash(self) -> str:
        return self.digest.hex()


@dataclass
class AddResult:
    status: str                      # accepted | duplicate | orphan | invalid
    reorg_depth: int = 0
    tip_changed: bool = False


class Chain:
    def __init__(self, genesis_balances=None, check_pow: bool = False, base_target=None):
        self.check_pow, self.base_target = check_pow, base_target
        self.genesis = Block(0, GENESIS_PARENT, (), "genesis")
        gh = self.genesis.hash
        self.blocks = {gh: self.genesis}                 # losing branches are KEPT
        self.states = {gh: State(genesis_balances)}
        self.work = {gh: 0}
        self.tip = gh
        self.orphans: dict[str, list[Block]] = {}
        self.reorg_depths: list[int] = []

    # ---------- queries ----------
    @property
    def height(self) -> int:
        return self.blocks[self.tip].height

    @property
    def state(self) -> State:
        return self.states[self.tip]

    def canonical(self) -> list[Block]:
        out, h = [], self.tip
        while h != GENESIS_PARENT:
            b = self.blocks[h]
            out.append(b)
            h = b.parent
        return out[::-1]

    def canonical_txids(self) -> set[str]:
        return {t.txid for b in self.canonical() for t in b.txs}

    def _ancestor_height(self, a: str, b: str) -> int:
        seen = set()
        while a != GENESIS_PARENT:
            seen.add(a); a = self.blocks[a].parent
        while b not in seen:
            b = self.blocks[b].parent
        return self.blocks[b].height

    # ---------- adding blocks ----------
    def add_block(self, block: Block) -> AddResult:
        h = block.hash
        if h in self.blocks:
            return AddResult("duplicate")
        if block.parent not in self.blocks:
            self.orphans.setdefault(block.parent, []).append(block)
            return AddResult("orphan")
        res = self._connect(block)
        queue = [h] if res.status == "accepted" else []
        while queue:                                     # adopt orphans whose parent just arrived
            for child in self.orphans.pop(queue.pop(), []):
                r = self._connect(child)
                if r.status == "accepted":
                    queue.append(child.hash)
                    res.reorg_depth = max(res.reorg_depth, r.reorg_depth)
                    res.tip_changed |= r.tip_changed
        return res

    def _connect(self, block: Block) -> AddResult:
        parent = self.blocks[block.parent]
        if block.height != parent.height + 1:
            return AddResult("invalid")
        if self.check_pow:
            from .pow import meets_target
            if not meets_target(block, self.base_target):
                return AddResult("invalid")
        st = self.states[block.parent].copy()
        try:
            st.balances[block.miner] = st.balances.get(block.miner, 0) + REWARD
            for tx in block.txs:
                st.apply(tx)
        except InvalidBlock:
            return AddResult("invalid")
        h = block.hash
        self.blocks[h], self.states[h] = block, st
        self.work[h] = self.work[block.parent] + block.difficulty
        depth, changed = 0, False
        if self.work[h] > self.work[self.tip]:           # strictly greater: ties keep the first-seen tip
            if block.parent != self.tip:
                depth = self.blocks[self.tip].height - self._ancestor_height(self.tip, h)
                self.reorg_depths.append(depth)
            self.tip, changed = h, True
        return AddResult("accepted", depth, changed)
