"""Part D: what post-quantum signatures cost a blockchain, and which coins Shor can reach."""

BASE_OVERHEAD = 110            # bytes of a 1-in-2-out tx that are not key+signature (215 - 72 - 33)
BLOCK_BYTES, BLOCK_SECONDS = 1_000_000, 600

# name: (public key bytes, signature bytes, post-quantum?)
SCHEMES = {
    "ECDSA (secp256k1)": (33, 72, False),
    "Schnorr (BIP-340)": (32, 64, False),
    "FN-DSA-512":        (897, 666, True),
    "ML-DSA-44":         (1312, 2420, True),
    "ML-DSA-65":         (1952, 3309, True),
    "SLH-DSA-128s":      (32, 7856, True),
}


def comparison_table():
    base = BASE_OVERHEAD + sum(SCHEMES["ECDSA (secp256k1)"][:2])
    rows = []
    for name, (pk, sig, pq) in SCHEMES.items():
        tx = BASE_OVERHEAD + pk + sig
        rows.append({"scheme": name, "pk": pk, "sig": sig, "tx_bytes": tx, "ratio": tx / base,
                     "tps": BLOCK_BYTES / tx / BLOCK_SECONDS, "post_quantum": pq})
    return rows


EXPOSURE = {   # kind: (exposed to Shor?, reason)
    "p2pkh_unspent": (False, "only HASH160(pubkey) is public until the coin is spent"),
    "p2pk": (True, "the full public key sits in the output"),
    "reused_address": (True, "an earlier spend already revealed the public key"),
    "mempool_transaction": (True, "the spend reveals the key while it waits for confirmation"),
    "ethereum_any_active": (True, "ecrecover derives the public key from any past signature"),
}


def exposure_report():
    return {k: ("EXPOSED" if e else "PROTECTED", why) for k, (e, why) in EXPOSURE.items()}
