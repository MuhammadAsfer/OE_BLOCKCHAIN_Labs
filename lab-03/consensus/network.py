"""Part C: gossip. Nodes keep their own chain + mempool, flood to peers, can be partitioned and healed."""
import asyncio
import random

from .chain import Block, Chain, Tx


class Node:
    def __init__(self, name, net, hash_share=1.0):
        self.name, self.net, self.hash_share = name, net, hash_share
        self.chain = Chain()
        self.known_txs: dict[str, Tx] = {}
        self.mempool: dict[str, Tx] = {}
        self.seen: set = set()                 # dedup filter: every message is processed once
        self.processed = 0

    def _prune_mempool(self):
        """Pending = everything we know minus what is in the CANONICAL chain.
        Txs that were only in orphaned blocks come back automatically."""
        done = self.chain.canonical_txids()
        self.mempool = {i: t for i, t in self.known_txs.items() if i not in done}

    async def receive(self, kind, payload, sender):
        key = (kind, payload.txid if kind == "tx" else payload if kind in ("inv", "getblock") else payload.hash)
        if kind == "getblock":                              # requests are answered, never deduped
            blk = self.chain.blocks.get(payload)
            if blk:
                await self.net.send(self.name, sender, "block", blk)
            return
        if key in self.seen:
            return
        self.seen.add(key)
        self.processed += 1
        if kind == "tx":
            self.known_txs[payload.txid] = payload
            self._prune_mempool()
            await self.net.flood(self.name, "tx", payload, exclude=sender)
        elif kind == "block":
            res = self.chain.add_block(payload)
            if res.status == "orphan":
                await self.net.send(self.name, sender, "getblock", payload.parent)
                self.seen.discard(("getblock", payload.parent))
            elif res.status == "accepted":
                for t in payload.txs:
                    self.known_txs.setdefault(t.txid, t)
                self._prune_mempool()
                await self.net.flood(self.name, "block", payload, exclude=sender)
        elif kind == "inv":                                  # head announcement
            if payload not in self.chain.blocks:
                await self.net.send(self.name, sender, "getblock", payload)

    def mine_one(self):
        txs, st = [], self.chain.state.copy()
        for t in sorted(self.mempool.values(), key=lambda t: (t.sender, t.nonce)):
            try:
                st.apply(t); txs.append(t)
            except Exception:
                pass
        parent = self.chain.blocks[self.chain.tip]
        blk = Block(parent.height + 1, self.chain.tip, tuple(txs), self.name, 1,
                    self.net.rng.getrandbits(32), parent.height + 1)
        return blk


class Network:
    def __init__(self, n=8, mean_block_time=0.25, latency=0.01, seed=None):
        self.rng = random.Random(seed)
        self.mean, self.latency = mean_block_time, latency
        self.nodes = {f"n{i}": Node(f"n{i}", self, 1 / n) for i in range(n)}
        names = list(self.nodes)
        self.links = {a: set() for a in names}
        for i, a in enumerate(names):                         # ring + one chord each
            for b in (names[(i + 1) % n], names[(i + n // 2) % n]):
                if a != b:
                    self.links[a].add(b); self.links[b].add(a)
        self.all_links = {a: set(s) for a, s in self.links.items()}
        self.groups = None
        self.running, self.tasks = False, set()

    # ---------- delivery ----------
    async def send(self, src, dst, kind, payload):
        if dst not in self.links[src]:
            return
        t = asyncio.create_task(self._deliver(src, dst, kind, payload))
        self.tasks.add(t); t.add_done_callback(self.tasks.discard)

    async def _deliver(self, src, dst, kind, payload):
        await asyncio.sleep(self.latency * (0.5 + self.rng.random()))
        await self.nodes[dst].receive(kind, payload, src)

    async def flood(self, src, kind, payload, exclude=None):
        for peer in self.links[src]:
            if peer != exclude:
                await self.send(src, peer, kind, payload)

    # ---------- topology control ----------
    def partition(self, group_a):
        a = set(group_a)
        self.groups = (a, set(self.nodes) - a)
        for n in self.links:
            self.links[n] = {p for p in self.all_links[n] if (n in a) == (p in a)}

    async def heal(self):
        self.groups = None
        self.links = {n: set(s) for n, s in self.all_links.items()}
        await self.announce_heads()

    async def announce_heads(self):
        for n in self.nodes.values():
            await self.flood(n.name, "inv", n.chain.tip)
            n.seen = {k for k in n.seen if k[0] != "inv"}

    # ---------- mining & running ----------
    async def _miner(self, node):
        while self.running:
            await asyncio.sleep(self.rng.expovariate(node.hash_share / self.mean))
            if not self.running:
                return
            blk = node.mine_one()
            node.seen.add(("block", blk.hash))
            res = node.chain.add_block(blk)
            if res.status == "accepted":
                node._prune_mempool()
                await self.flood(node.name, "block", blk)

    async def run_for(self, seconds, announce_every=0.2):
        self.running = True
        miners = [asyncio.create_task(self._miner(n)) for n in self.nodes.values()]
        end = asyncio.get_event_loop().time() + seconds
        while asyncio.get_event_loop().time() < end:
            await asyncio.sleep(announce_every)
            await self.announce_heads()                      # periodic head announcements
        self.running = False
        await asyncio.gather(*miners, return_exceptions=True)
        await asyncio.sleep(self.latency * 4)

    def tips(self):
        return {n.chain.tip: n.chain.height for n in self.nodes.values()}
