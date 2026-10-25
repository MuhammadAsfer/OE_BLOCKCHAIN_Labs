"""Part A: proof of work. Hash the header until it is <= target; retarget; parallel search."""
import multiprocessing as mp
import hashlib
import statistics
import time
from dataclasses import dataclass, field

from .chain import Block, Chain, header_prefix

MAX = 2**256 - 1
GENESIS_TARGET = MAX >> 16               # p ~ 2^-16 per hash  ->  ~65 536 hashes per block


def difficulty_to_target(d: int, base=None) -> int:
    return (base or GENESIS_TARGET) // d


def target_to_difficulty(t: int, base=None) -> int:
    return (base or GENESIS_TARGET) // t


def meets_target(block: Block, base=None) -> bool:
    return int.from_bytes(block.digest, "big") <= difficulty_to_target(block.difficulty, base)


def retarget(difficulty: int, actual: float, expected: float, clamp: int = 4) -> int:
    """Window was fast -> harder, slow -> easier. Ratio is clamped to [1/4, 4]."""
    if actual <= 0:
        actual = expected / clamp
    ratio = max(1 / clamp, min(clamp, actual / expected))
    return max(1, int(difficulty / ratio))


def _search(prefix: bytes, target: int, start: int, stride: int, stop=None, limit=None):
    n, sha = start, hashlib.sha256
    tries = 0
    while True:
        d = sha(sha(prefix + str(n).encode()).digest()).digest()
        if int.from_bytes(d, "big") <= target:
            return n
        n += stride
        tries += 1
        if limit and tries >= limit:
            return None
        if stop is not None and tries % 2048 == 0 and stop.is_set():
            return None


def _worker(prefix, target, start, stride, stop, out):          # module level: picklable under spawn
    n = _search(prefix, target, start, stride, stop)
    if n is not None:
        out.put(n)
        stop.set()


def mine_block(height, parent, txs, miner, difficulty, timestamp=0, base=None, start=0) -> Block:
    probe = Block(height, parent, tuple(txs), miner, difficulty, 0, timestamp)
    prefix = header_prefix(height, parent, probe.merkle, timestamp, difficulty, miner)
    n = _search(prefix, difficulty_to_target(difficulty, base), start, 1)
    return Block(height, parent, tuple(txs), miner, difficulty, n, timestamp)


def mine_parallel(height, parent, txs, miner, difficulty, timestamp=0, workers=2, base=None, timeout=120) -> Block:
    """Strided search: worker i tries nonces i, i+W, i+2W ... New processes per call (slow start-up!)."""
    ctx = mp.get_context("spawn")
    probe = Block(height, parent, tuple(txs), miner, difficulty, 0, timestamp)
    prefix = header_prefix(height, parent, probe.merkle, timestamp, difficulty, miner)
    target = difficulty_to_target(difficulty, base)
    stop, out = ctx.Event(), ctx.Queue()
    procs = [ctx.Process(target=_worker, args=(prefix, target, i, workers, stop, out)) for i in range(workers)]
    for p in procs:
        p.start()
    try:
        n = out.get(timeout=timeout)
    finally:
        stop.set()
        for p in procs:
            p.join(5)
            if p.is_alive():
                p.terminate()
    return Block(height, parent, tuple(txs), miner, difficulty, n, timestamp)


@dataclass
class MiningStats:
    intervals: list = field(default_factory=list)
    difficulties: list = field(default_factory=list)

    @property
    def mean(self): return statistics.fmean(self.intervals)
    @property
    def median(self): return statistics.median(self.intervals)
    @property
    def stdev(self): return statistics.stdev(self.intervals)
    @property
    def median_over_mean(self): return self.median / self.mean
    @property
    def stdev_over_mean(self): return self.stdev / self.mean


def simulate_mining(blocks=100, workers=1, target_seconds=0.3, window=10, base=None):
    chain = Chain(check_pow=True, base_target=base)
    stats = MiningStats()
    difficulty, win_start = 1, time.perf_counter()
    for h in range(1, blocks + 1):
        t0 = time.perf_counter()
        if workers == 1:
            b = mine_block(h, chain.tip, [], "miner", difficulty, h, base)
        else:
            b = mine_parallel(h, chain.tip, [], "miner", difficulty, h, workers, base)
        stats.intervals.append(time.perf_counter() - t0)
        assert chain.add_block(b).status == "accepted"
        if h % window == 0:
            now = time.perf_counter()
            difficulty = retarget(difficulty, now - win_start, window * target_seconds)
            stats.difficulties.append(difficulty)
            win_start = now
    return chain, stats
