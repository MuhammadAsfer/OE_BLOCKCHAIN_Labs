# Study Guide: understand what the code does (read this before you submit)

The rule you were given is "AI is fine as long as you understand". The oral exam and the report's
"explain the why" parts test exactly that. For each lab: read the code in the order listed, then try
to answer the questions **out loud without looking**. If you can't, re-read that function.

---
## Lab 01 - Bitcoin transactions (`lab-01/txparser`)

**Read in this order:** `compactsize.py` -> `reader.py` -> `tx.py` -> `script.py`.

**The 5 ideas**
1. **A transaction is bytes with a fixed layout.** version(4) | [marker 00, flag 01 if SegWit] | #inputs | inputs | #outputs | outputs | [witness] | locktime(4). All integers are little-endian.
2. **CompactSize**: <253 -> 1 byte; otherwise prefix fd/fe/ff + 2/4/8 bytes little-endian. 300 = `fd 2c 01`.
3. **txid = reversed sha256d of the legacy serialisation** (no marker/flag/witness). wtxid includes witness. That split is the malleability fix.
4. **weight = 3 x stripped + total; vsize = ceil(weight/4).** Our sample: 3x113+222 = 561 WU -> 141 vB.
5. **There is no fee field.** fee = sum(inputs) - sum(outputs). The parser can't print it because an input only names `txid:vout`; the value lives in an older transaction.

**Why the code is written this way**
- `Reader.read` checks bounds -> truncated hex raises instead of returning garbage ("robustness" row).
- `parse_transaction` raises on trailing bytes -> a parser must refuse, not ignore.
- Marker detection `00 01`: a real tx can't have 0 inputs, so a 0 in the input-count position is unambiguous.
- Values are Python ints in satoshis, never floats.

**Explain out loud**
- Why does input 0 start at byte 7 in SegWit but 5 in legacy?
- Why do we reverse prev-txid bytes for display?
- Why is `-25` in Part D not a consensus rule? (RPC `maxfeerate` guard; consensus only needs sum(in) >= sum(out).)
- Why does Ethereum not have the "forgot the change" problem? (accounts, not outputs.)

**Your Docker parts (I could not run these):** setup, Part A, B, D. The README commands are in `docs/LAB01_RUNBOOK.md`.

---
## Lab 02 - Keys and crypto (`lab-02`)

**Read:** `curve.py` -> `ecdsa.py` -> `hdwallet.py` -> `address.py` -> `pqc.py`.

**The math in plain words**
- Everything is arithmetic **mod p** (coordinates) or **mod n** (scalars). Mixing them is a classic bug.
- "Division" = multiply by the **modular inverse**; `inverse_mod` uses Fermat: `a^(p-2) mod p`.
- Point addition: slope lambda, then x3 = lambda^2 - x1 - x2, y3 = lambda(x1-x3) - y1. Special cases: P+O, P+(-P)=O, doubling with y=0.
- `scalar_mul` = Double-and-Add (extra add only on 1-bits -> timing leak). `scalar_mul_ladder` does the same work every bit.
- **ECDSA:** s = k^-1 (z + r d). Verify: (u1 G + u2 Q).x == r.
- **Nonce reuse:** same k -> same r. Then s1 k = z1 + r d and s2 k = z2 + r d. Subtract -> k = (z1-z2)/(s1-s2); then d = (s1 k - z1)/r. Because low-s may flip either s, we try all four sign combinations and keep the one with d*G == Q.
- **RFC 6979:** k = HMAC-DRBG(d, z). Unique per message, unguessable without d.
- **Low-s:** (r,s) and (r,n-s) both verify -> malleability; flipping s = negating k, so the recovery id parity flips too.
- **BIP-39/32/44:** words -> PBKDF2(2048 rounds, salt = "mnemonic"+passphrase) -> HMAC-SHA512("Bitcoin seed") -> master key + chain code -> child = (I_L + parent) mod n. Hardened index = i + 2^31 and uses the parent *private* key in the HMAC.
- **xpub leak:** for a normal child I_L uses only public data, so parent = child - I_L. Hardened levels block it. That is why BIP-44 hardens purpose/coin/account.
- **Ethereum address:** Keccak-256 (not SHA3-256!) of x||y, last 20 bytes; EIP-55 capitalisation = checksum from Keccak of the lowercase hex *string*.
- **Post-quantum:** tx size = 110 bytes overhead + pubkey + signature. ML-DSA-44: 1312+2420+110 = 3842 B (17.9x ECDSA). Shor needs the public key: unspent P2PKH is protected, P2PK/reused/mempool/active-Ethereum are exposed. "Harvest now, break later" -> migrate now.

**Explain out loud**
- Why does a valid signature still leak the key when k is reused?
- Why does RFC 6979 not make k public?
- Why does one extra trailing space in a passphrase look exactly like theft?
- Why is `/` wrong in field arithmetic and why does it fail silently?

**Honest note:** my demo key in `python -m crypto_lab` is my own (the companion only shows its first digits), so the demo address differs from the companion's `0xa0f5...0C09`. All published vectors (2G, abandon seed, 3 addresses, EIP-55, BIP-84, RFC 6979, Keccak("")) do match.

---
## Lab 03 - Consensus (`lab-03`)

**Read:** `chain.py` -> `pow.py` -> `pos.py` -> `network.py` -> `cli.py`.

- **chain.py:** account state (balance + sequential nonce -> replay protection) and a *block tree*. The tip moves only on **strictly greater** work, so equal branches stay tied; losing branches are **kept**; reorg depth = old-tip blocks beyond the common ancestor. Bug I hit while writing it: the header did not include the miner, so two different blocks hashed the same - the test `equal_work_does_not_move_tip` caught it.
- **pow.py:** hash header until <= target (`MAX >> 16` -> ~65,536 hashes). Waiting time is geometric/exponential, so median/mean = ln2 = 0.693 and stdev/mean = 1. Memorylessness is why mining is fair. `retarget` clamps the ratio to [1/4, 4]. `--workers 1` for statistics, because spawning processes per block (~1 s) is slower than mining a block.
- **pos.py (Casper FFG):** *justified* = a link from a justified source carries **> 2/3** of active stake; *finalised* = justified and its immediate successor justified. Strictly more than 2/3 because two conflicting 2/3 sets must overlap in > 1/3 that double-voted (slashable). Slashing: initial = balance/32, then correlated = balance x min(1, 3 x slashed/total) -> 1 offender loses 2.41 ETH, 20 together lose 29.43. Inactivity leak after a 4-epoch grace period drains absent validators (1.6 %/epoch here) until the present ones exceed 2/3 (~epoch 81).
- **network.py:** flood gossip with a dedup set (each message processed once), `partition()`/`heal()`, periodic head announcements (without them healed nodes never learn the other tip). `_prune_mempool` keeps only txs not in the canonical chain, so txs from orphaned blocks reappear: probabilistic finality.

**Explain out loud**
- Why is median < mean for block intervals?
- Why does Casper stall instead of continuing with fewer validators? (safety over liveness; CAP)
- Why can two nodes show different tips at the same height after healing and that's *not* a bug?
- Why do reorgs get deeper with longer partitions?

**Not implemented:** the "Hard" practice items (O(n log n) violation detection, stale-rate plot) and all "Beyond the labs" items. They are ungraded.

---
## Fast oral-exam drill (2 minutes per lab)
Open the interactive companion tools (fee calculator, toy curve, ECDSA attack, slashing calculator) and re-derive one number by hand per lab. If you can do that, you understand the lab.
