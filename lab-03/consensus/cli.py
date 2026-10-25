import argparse
import asyncio
import statistics
import sys

from . import pow as powmod
from .pos import BeaconState, Checkpoint, Attestation, GWEI
from .network import Network
from .chain import Tx


def run_pow(blocks=100, workers=1):
    print(f"== Part A: mining {blocks} blocks, workers={workers} ==")
    chain, s = powmod.simulate_mining(blocks=blocks, workers=workers)
    print(f"mean {s.mean:.3f}s  median {s.median:.3f}s  stdev {s.stdev:.3f}s")
    print(f"median/mean {s.median_over_mean:.3f} (theory 0.693)   stdev/mean {s.stdev_over_mean:.3f} (theory 1.0)")
    print(f"min {min(s.intervals):.4f}s  max {max(s.intervals):.3f}s  span {max(s.intervals)/min(s.intervals):.0f}x")
    print("retarget(1000,300,600) =", powmod.retarget(1000, 300, 600), " (1000,1200,600) =", powmod.retarget(1000, 1200, 600),
          " (1000,6,600) =", powmod.retarget(1000, 6, 600), " (1000,60000,600) =", powmod.retarget(1000, 60000, 600))
    cnt = [0] * 12
    top = max(s.intervals)
    for x in s.intervals:
        cnt[min(11, int(x / top * 12))] += 1
    print("histogram (12 bins from 0 to max):")
    for i, c in enumerate(cnt):
        print(f"  {i * top / 12:6.2f}s | {'#' * c}")


def _vote(state, validators, src, tgt):
    for i in validators:
        state.attest(Attestation(i, src, tgt))


def run_pos():
    print("== Part B: Casper FFG ==")
    s = BeaconState(64)
    g, prev = s.genesis_checkpoint, s.genesis_checkpoint
    print("-- Scenario 1: finality")
    for e in (1, 2, 3):
        cp = Checkpoint(e, f"root-{e}")
        _vote(s, range(64), s.current_justified, cp)
        r = s.process_epoch(e)
        print(f"  epoch {e}: justified {r['justified']}  finalized {r['finalized']}")
    for k, label in ((1, "Scenario 2: one equivocator"), (20, "Scenario 3: twenty at once")):
        s = BeaconState(64)
        g, A, B = s.genesis_checkpoint, Checkpoint(1, "chain-A"), Checkpoint(1, "chain-B")
        _vote(s, range(64), g, A); _vote(s, range(k), g, B)
        s.process_epoch(1)
        print(f"-- {label}: loss each {(INIT - s.validators[0].balance) / GWEI:.4f} ETH")
    s = BeaconState(64)
    g = s.genesis_checkpoint
    _vote(s, [0], Checkpoint(1, "a"), Checkpoint(4, "d")); _vote(s, [0], Checkpoint(2, "b"), Checkpoint(3, "c"))
    s.process_epoch(4)
    print("-- Scenario 4: surround vote ->", s.validators[0].slash_reason)
    print("-- Slashing table (64 validators):")
    for k in (1, 5, 10, 20, 30):
        s = BeaconState(64)
        g, A, B = s.genesis_checkpoint, Checkpoint(1, "chain-A"), Checkpoint(1, "chain-B")
        _vote(s, range(64), g, A); _vote(s, range(k), g, B)
        s.process_epoch(1)
        print(f"   {k:2d} offenders -> {(INIT - s.validators[0].balance) / GWEI:6.2f} ETH each")
    print("-- Scenario 5: inactivity leak (24 of 64 present, 100 epochs)")
    s = BeaconState(64)
    for e in range(1, 101):
        cp = Checkpoint(e, f"r{e}")
        _vote(s, range(24), s.current_justified, cp)
        r = s.process_epoch(e)
        if e in (1, 5, 11, 20, 40, 60, 80, 82, 90, 100):
            print(f"   epoch {e:3d}: voting share {r['voting_share']*100:5.1f}%  leaking={r['leaking']}  "
                  f"justified={r['justified'] is not None}  finalized epoch={r['finalized'].epoch}")


INIT = 32 * GWEI


async def _run_gossip(nodes=8, mean_block_time=0.25, seed=None):
    net = Network(nodes, mean_block_time, latency=mean_block_time * 0.04, seed=seed)
    names = list(net.nodes)
    for n in net.nodes.values():
        n.chain.state.balances["alice"] = 1000
    await net.run_for(mean_block_time * 6)
    print(f"connected phase : tips={len(net.tips())}")
    net.partition(names[: nodes // 2])
    await net.nodes[names[0]].receive("tx", Tx("alice", "bob", 5, 0), "client")
    await net.run_for(mean_block_time * 10)
    print(f"partitioned     : distinct tips={len(net.tips())}  heights={sorted(set(net.tips().values()))}")
    await net.heal()
    await net.run_for(mean_block_time * 6)
    heights = sorted(set(net.tips().values()))
    print(f"after heal      : distinct tips={len(net.tips())}  heights={heights}  converged={len(net.tips()) == 1}")
    return net


def run_gossip(nodes=8, seed=None):
    print("== Part C: gossip, partition, heal ==")
    net = asyncio.run(_run_gossip(nodes, seed=seed))
    print("reorg depths per node:", {n: x.chain.reorg_depths for n, x in net.nodes.items()})


def main():
    ap = argparse.ArgumentParser(prog="consensus")
    ap.add_argument("part", nargs="?", choices=["pow", "pos", "gossip"])
    ap.add_argument("--blocks", type=int, default=100)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--nodes", type=int, default=8)
    ap.add_argument("--seed", type=int, default=None)
    a = ap.parse_args()
    if a.part in (None, "pow"): run_pow(a.blocks, a.workers)
    if a.part in (None, "pos"): run_pos()
    if a.part in (None, "gossip"): run_gossip(a.nodes, a.seed)
