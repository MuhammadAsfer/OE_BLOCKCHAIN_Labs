"""Part B: a Casper FFG state machine (abstract checkpoints): justify, finalise, slash, leak."""
from dataclasses import dataclass, field

GWEI = 10**9
INITIAL_BALANCE = 32 * GWEI
MIN_SLASHING_PENALTY_QUOTIENT = 32
LEAK_GRACE_EPOCHS = 4
LEAK_RATE_PPM = 16_000                  # 1.6 % of balance per epoch for absent validators


@dataclass(frozen=True)
class Checkpoint:
    epoch: int
    root: str


@dataclass(frozen=True)
class Attestation:
    validator: int
    source: Checkpoint
    target: Checkpoint


@dataclass
class Validator:
    balance: int = INITIAL_BALANCE
    slashed: bool = False
    slash_reason: str | None = None


def find_violations(atts):
    """All-pairs check. Returns [(validator, reason)]: 'double_vote' or 'surround_vote'."""
    out, by_val = [], {}
    for a in atts:
        by_val.setdefault(a.validator, []).append(a)
    for v, lst in by_val.items():
        reason = None
        for i, a in enumerate(lst):
            for b in lst[i + 1:]:
                if a.target.epoch == b.target.epoch and a.target != b.target:
                    reason = reason or "double_vote"
                s1, t1, s2, t2 = a.source.epoch, a.target.epoch, b.source.epoch, b.target.epoch
                if (s1 < s2 and t2 < t1) or (s2 < s1 and t1 < t2):
                    reason = "surround_vote"
        if reason:
            out.append((v, reason))
    return out


class BeaconState:
    def __init__(self, validator_count=64):
        self.validators = [Validator() for _ in range(validator_count)]
        self.genesis_checkpoint = Checkpoint(0, "genesis")
        self.justified = {self.genesis_checkpoint}
        self.current_justified = self.genesis_checkpoint
        self.finalized = self.genesis_checkpoint
        self.attestations: list[Attestation] = []
        self.epoch = 0
        self.history = []                # per-epoch dict for reports

    # ---------- stake helpers ----------
    def total_active(self) -> int:
        return sum(v.balance for v in self.validators if not v.slashed)

    def attest(self, a: Attestation):
        self.attestations.append(a)

    # ---------- the epoch transition ----------
    def process_epoch(self, epoch: int):
        self.epoch = epoch
        atts = [a for a in self.attestations if a.target.epoch == epoch]
        active_before = self.total_active()

        # 1. slashing: initial penalty, then the correlated penalty over everyone slashed now
        fresh = [(v, r) for v, r in find_violations(self.attestations) if not self.validators[v].slashed]
        for v, reason in fresh:
            val = self.validators[v]
            val.balance -= val.balance // MIN_SLASHING_PENALTY_QUOTIENT
            val.slashed, val.slash_reason = True, reason
        if fresh:
            slashed_total = sum(self.validators[v].balance for v, _ in fresh)
            total = self.total_active() + slashed_total
            for v, _ in fresh:
                val = self.validators[v]
                val.balance -= val.balance * min(3 * slashed_total, total) // total

        # 2. justification: strictly more than 2/3 of active stake on one link from a justified source
        threshold = 2 * active_before // 3
        weight: dict = {}
        for a in atts:
            if not self.validators[a.validator].slashed and a.source in self.justified:
                weight.setdefault((a.source, a.target), set()).add(a.validator)
        justified_now = None
        for (src, tgt), voters in weight.items():
            if sum(self.validators[v].balance for v in voters) > threshold:
                self.justified.add(tgt)
                self.current_justified = tgt if tgt.epoch >= self.current_justified.epoch else self.current_justified
                justified_now = tgt
                # 3. finalisation: source finalised when target is its immediate successor
                if tgt.epoch == src.epoch + 1 and src.epoch > self.finalized.epoch:
                    self.finalized = src

        # 4. inactivity leak after the grace period: drain validators who did not attest
        leaking = epoch - self.finalized.epoch > LEAK_GRACE_EPOCHS
        if leaking:
            present = {a.validator for a in atts}
            for i, val in enumerate(self.validators):
                if not val.slashed and i not in present:
                    val.balance -= val.balance * LEAK_RATE_PPM // 1_000_000
        present = {a.validator for a in atts if not self.validators[a.validator].slashed}
        share = sum(self.validators[i].balance for i in present) / max(1, self.total_active())
        self.history.append({"epoch": epoch, "justified": justified_now, "finalized": self.finalized,
                             "leaking": leaking, "voting_share": share})
        return self.history[-1]
