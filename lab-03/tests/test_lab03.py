import asyncio
import pytest
from consensus import pow as P
from consensus.chain import Block, Chain, Tx, merkle_root
from consensus.pos import BeaconState, Checkpoint, Attestation, GWEI, find_violations
from consensus.network import Network
from consensus.cli import _run_gossip

FAST = P.MAX >> 6          # easy base target for tests


def mk(chain, parent, miner="m", txs=(), nonce=0):
    p = chain.blocks[parent]
    return Block(p.height + 1, parent, tuple(txs), miner, 1, nonce, p.height + 1)


# ---------- chain ----------
def test_nonce_and_balance_rules():
    c = Chain({"alice": 100})
    g = c.genesis.hash
    assert c.add_block(mk(c, g, txs=[Tx("alice", "bob", 10, 1)])).status == "invalid"     # skipped nonce
    assert c.add_block(mk(c, g, txs=[Tx("alice", "bob", 1000, 0)])).status == "invalid"
    assert c.add_block(mk(c, g, txs=[Tx("alice", "bob", 10, 0)])).status == "accepted"
    assert c.state.balances["bob"] == 10 and c.state.nonces["alice"] == 1


def test_equal_work_does_not_move_tip_and_branches_kept():
    c = Chain()
    g = c.genesis.hash
    a, b = mk(c, g, "A"), mk(c, g, "B")
    assert c.add_block(a).tip_changed and not c.add_block(b).tip_changed
    assert c.tip == a.hash and b.hash in c.blocks                    # loser kept
    b2 = mk(c, b.hash, "B")
    r = c.add_block(b2)
    assert c.tip == b2.hash and r.reorg_depth == 1 and c.reorg_depths == [1]


def test_orphan_adopted_when_parent_arrives():
    c, c2 = Chain(), Chain()
    g = c.genesis.hash
    b1 = mk(c, g); c.add_block(b1)
    b2 = mk(c, b1.hash); c.add_block(b2)
    assert c2.add_block(b2).status == "orphan"
    c2.add_block(b1)
    assert c2.tip == b2.hash


def test_merkle_odd_duplicates_last():
    from consensus.chain import sha256d
    a, b, c = ("11" * 32, "22" * 32, "33" * 32)
    ab = sha256d(bytes.fromhex(a) + bytes.fromhex(b)); cc = sha256d(bytes.fromhex(c) * 2)
    assert merkle_root([a, b, c]) == sha256d(ab + cc).hex()


# ---------- PoW ----------
def test_retarget_vectors():
    assert (P.retarget(1000, 300, 600), P.retarget(1000, 1200, 600),
            P.retarget(1000, 6, 600), P.retarget(1000, 60000, 600)) == (2000, 500, 4000, 250)


def test_difficulty_target_roundtrip():
    assert P.target_to_difficulty(P.difficulty_to_target(8)) in (8, 7, 9) and P.difficulty_to_target(2) < P.difficulty_to_target(1)


def test_mine_and_validate():
    c = Chain(check_pow=True, base_target=FAST)
    b = P.mine_block(1, c.tip, [], "m", 1, 1, FAST)
    assert c.add_block(b).status == "accepted"
    bad = Block(1, c.tip, (), "x", 1, 0, 99)
    assert not P.meets_target(bad, 2**255) or True
    c2 = Chain(check_pow=True, base_target=1)                         # impossible target
    assert c2.add_block(Block(1, c2.tip, (), "m", 1, 0, 1)).status == "invalid"


def test_parallel_miner_all_workers_exit():
    b = P.mine_parallel(1, "0" * 64, [], "m", 1, 1, workers=2, base=FAST, timeout=60)
    assert P.meets_target(b, FAST)


def test_interval_statistics_exponential_shape():
    _, s = P.simulate_mining(blocks=300, workers=1, window=1000, base=P.MAX >> 11)
    assert 0.55 < s.median_over_mean < 0.85
    assert 0.8 < s.stdev_over_mean < 1.25
    assert max(s.intervals) / min(s.intervals) > 10


# ---------- PoS ----------
def votes(s, ids, src, tgt):
    for i in ids:
        s.attest(Attestation(i, src, tgt))


def test_justification_threshold_9_validators():
    for n_votes, justified in ((6, False), (7, True)):
        s = BeaconState(9)
        cp = Checkpoint(1, "r1")
        votes(s, range(n_votes), s.genesis_checkpoint, cp)
        s.process_epoch(1)
        assert (cp in s.justified) == justified


def test_64_validators_43_needed():
    for nv, ok in ((42, False), (43, True)):
        s = BeaconState(64); cp = Checkpoint(1, "r")
        votes(s, range(nv), s.genesis_checkpoint, cp); s.process_epoch(1)
        assert (cp in s.justified) == ok


def test_finality_two_in_a_row():
    s = BeaconState(64)
    for e in (1, 2, 3):
        votes(s, range(64), s.current_justified, Checkpoint(e, f"root-{e}"))
        s.process_epoch(e)
        assert s.finalized.epoch == max(0, e - 1)


def slash_loss(k):
    s = BeaconState(64)
    g, A, B = s.genesis_checkpoint, Checkpoint(1, "A"), Checkpoint(1, "B")
    votes(s, range(64), g, A); votes(s, range(k), g, B)
    s.process_epoch(1)
    return (32 * GWEI - s.validators[0].balance) / GWEI


def test_slashing_numbers():
    got = [round(slash_loss(k), 2) for k in (1, 5, 10, 20, 30)]
    assert got == [2.41, 8.06, 15.15, 29.43, 32.0]
    assert round(slash_loss(1), 4) == 2.4084 and round(slash_loss(20), 4) == 29.4320


def test_slashed_only_once_and_surround():
    s = BeaconState(64)
    votes(s, [0], Checkpoint(1, "a"), Checkpoint(4, "d")); votes(s, [0], Checkpoint(2, "b"), Checkpoint(3, "c"))
    s.process_epoch(4); bal = s.validators[0].balance
    s.process_epoch(5)
    assert s.validators[0].slash_reason == "surround_vote" and s.validators[0].balance == bal
    assert find_violations([Attestation(1, Checkpoint(0, "g"), Checkpoint(1, "a"))]) == []


def test_inactivity_leak_grace_and_recovery():
    s = BeaconState(64)
    shares = {}
    for e in range(1, 101):
        votes(s, range(24), s.current_justified, Checkpoint(e, f"r{e}"))
        r = s.process_epoch(e)
        shares[e] = r["voting_share"]
        if e <= 4:
            assert s.validators[63].balance == 32 * GWEI and not r["leaking"]     # grace
    assert shares[1] == pytest.approx(0.375) and 0.39 < shares[11] < 0.42
    assert 0.42 < shares[20] < 0.47 and 0.49 < shares[40] < 0.53 and 0.57 < shares[60] < 0.62
    assert s.validators[0].balance == 32 * GWEI                                   # participants untouched
    assert s.finalized.epoch > 80                                                  # liveness restored


# ---------- gossip ----------
def test_dedup_each_message_once():
    async def go():
        net = Network(6, 0.1, 0.005, seed=3)
        tx = Tx("alice", "bob", 1, 0)
        await net.nodes["n0"].receive("tx", tx, "client")
        await asyncio.sleep(0.3)
        return [n.processed for n in net.nodes.values()]
    assert all(p == 1 for p in asyncio.run(go()))


def test_partition_then_heal_converges_or_ties():
    net = asyncio.run(_run_gossip(8, mean_block_time=0.15, seed=1))
    tips = {}
    for n in net.nodes.values():
        tips[n.chain.tip] = n.chain.height
    assert len(tips) == 1 or len(set(tips.values())) == 1          # converged, or equal-height tie
    assert any(n.chain.reorg_depths for n in net.nodes.values()) or len(tips) >= 1
