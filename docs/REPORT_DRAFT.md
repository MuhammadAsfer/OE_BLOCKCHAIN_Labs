# Introduction to Blockchain Programming - Labs 01-03 report

*Name / Neptun: ______*  (Replace every `TODO` with your own output; rewrite the explanations in your own words.)

## Lab 01 - Bitcoin regtest
**Setup output** (`getblockchaininfo`, `getbalance`): TODO paste.
**Part A.** Mature output `txid:vout` = TODO. `getbalances`: trusted 50, immature 5000. `gettxoutsetinfo`: height 101, txouts 101, total 5050.
Explanation: the node counts every unspent output; the wallet shows spendable ones; 101 not 202 because the OP_RETURN witness commitments are unspendable.
**Part B.** change = 50 - 10 - 0.0001 = 39.9999 BTC. Signed hex: TODO. decode/mempool/gettransaction outputs: TODO.
Expected shape: size 222, vsize 141, weight 561, fee -0.0001, fee rate 10 000 / 141 = 70.9 sat/vB.
**Part C (parser).** Output of `uv run python -m txparser <hex>`: TODO. Test result: `uv run pytest` = 19 passed (mine; yours may add more).
Explanation of txid vs wtxid, byte order, why input 0 is at byte 7, why the parser cannot print the fee: see Study Guide.
**Part D.** Error -25 text: TODO. Block output: coinbase 90 BTC = 50 + 40. Explanation: -25 is an RPC safety limit, not consensus; fee = sum(in) - sum(out).

## Lab 02 - Keys and cryptography
Tests: 27 passed. Demo output (generated with the submitted code):
```
== Part A: curve ==
G on curve : True
2G x       : c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
n*G = O    : True
P+(-P) = O : True
ladder == double-and-add: True
SEC1 round trip: True

== Part B: ECDSA ==
address    : 0x97a10005a72997fa009eA4366B38702A3A2f500F
verify     : True
(r, n-s) also verifies: True
deterministic: True
recover pubkey: True
identical r: True
original d : 0xc0ffee00112233445566778899aabbccddeeff00112233445566778899aabbcc
recovered d: 0xc0ffee00112233445566778899aabbccddeeff00112233445566778899aabbcc -> match: True

== Part C: HD wallet ==
seed       : 5eb00bbddcf06908...
m/44'/60'/0'/0/0: 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
m/44'/60'/0'/0/1: 0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0
m/44'/60'/0'/0/2: 0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A
passphrase 'correct horse'  : 0xFf0Bdf99513306994d4aF9949BA7cfA60204D285
passphrase 'correct horse ' : 0x67dA015b6A80F19822e5d270A7788F72f018a724
parent key recovered from child + xpub: True
watch-only derivation matches: True
hardened refused: hardened child: I_L cannot be computed without the parent private key

== Part D: post-quantum cost ==
scheme                  pk   sig   tx B  x ECDSA    tps
ECDSA (secp256k1)       33    72    215     1.0x   7.75
Schnorr (BIP-340)       32    64    206     1.0x   8.09
FN-DSA-512             897   666   1673     7.8x   1.00
ML-DSA-44             1312  2420   3842    17.9x   0.43
ML-DSA-65             1952  3309   5371    25.0x   0.31
SLH-DSA-128s            32  7856   7998    37.2x   0.21

Exposure report:
  p2pkh_unspent         PROTECTED  only HASH160(pubkey) is public until the coin is spent
  p2pk                  EXPOSED    the full public key sits in the output
  reused_address        EXPOSED    an earlier spend already revealed the public key
  mempool_transaction   EXPOSED    the spend reveals the key while it waits for confirmation
  ethereum_any_active   EXPOSED    ecrecover derives the public key from any past signature

```
**Explanations to write in your own words:** modular inverse vs `/`; Double-and-Add leak vs ladder; why nonce reuse reveals d and why four sign combinations are tried; why RFC 6979 fixes it; passphrase and deniability; Keccak vs SHA3; hardening and the xpub attack.
**Part D question (15-year migration):** migrate now - public keys on the ledger are permanent and can be harvested today; if migration takes years and assets must be safe for 15 years, waiting for a quantum forecast is already late. ML-DSA-44 costs 17.9x the transaction size and cuts throughput from 7.75 to 0.43 tps.

## Lab 03 - Consensus
Tests: 17 passed. Demo output (generated with the submitted code; timings vary by machine):
```
== Part B: Casper FFG ==
-- Scenario 1: finality
  epoch 1: justified Checkpoint(epoch=1, root='root-1')  finalized Checkpoint(epoch=0, root='genesis')
  epoch 2: justified Checkpoint(epoch=2, root='root-2')  finalized Checkpoint(epoch=1, root='root-1')
  epoch 3: justified Checkpoint(epoch=3, root='root-3')  finalized Checkpoint(epoch=2, root='root-2')
-- Scenario 2: one equivocator: loss each 2.4084 ETH
-- Scenario 3: twenty at once: loss each 29.4320 ETH
-- Scenario 4: surround vote -> surround_vote
-- Slashing table (64 validators):
    1 offenders ->   2.41 ETH each
    5 offenders ->   8.06 ETH each
   10 offenders ->  15.15 ETH each
   20 offenders ->  29.43 ETH each
   30 offenders ->  32.00 ETH each
-- Scenario 5: inactivity leak (24 of 64 present, 100 epochs)
   epoch   1: voting share  37.5%  leaking=False  justified=False  finalized epoch=0
   epoch   5: voting share  37.9%  leaking=True  justified=False  finalized epoch=0
   epoch  11: voting share  40.2%  leaking=True  justified=False  finalized epoch=0
   epoch  20: voting share  43.7%  leaking=True  justified=False  finalized epoch=0
   epoch  40: voting share  51.7%  leaking=True  justified=False  finalized epoch=0
   epoch  60: voting share  59.7%  leaking=True  justified=False  finalized epoch=0
   epoch  80: voting share  67.2%  leaking=True  justified=True  finalized epoch=0
   epoch  82: voting share  67.2%  leaking=False  justified=True  finalized epoch=81
   epoch  90: voting share  67.2%  leaking=False  justified=True  finalized epoch=89
   epoch 100: voting share  67.2%  leaking=False  justified=True  finalized epoch=99
== Part A: mining 100 blocks, workers=1 ==
mean 0.227s  median 0.167s  stdev 0.230s
median/mean 0.735 (theory 0.693)   stdev/mean 1.010 (theory 1.0)
min 0.0042s  max 1.410s  span 332x
retarget(1000,300,600) = 2000  (1000,1200,600) = 500  (1000,6,600) = 4000  (1000,60000,600) = 250
histogram (12 bins from 0 to max):
    0.00s | #########################################
    0.12s | ##########################
    0.23s | ###########
    0.35s | ###########
    0.47s | ##
    0.59s | #####
    0.70s | #
    0.82s | ##
    0.94s | 
    1.06s | 
    1.17s | 
    1.29s | #
== Part C: gossip, partition, heal ==
connected phase : tips=1
partitioned     : distinct tips=2  heights=[6, 11]
after heal      : distinct tips=1  heights=[12]  converged=True
reorg depths per node: {'n0': [], 'n1': [], 'n2': [], 'n3': [], 'n4': [], 'n5': [], 'n6': [1], 'n7': [1], 'n8': [1], 'n9': [1], 'n10': [1], 'n11': [1]}
== Part C: gossip, partition, heal ==
connected phase : tips=1
partitioned     : distinct tips=2  heights=[7, 8]
after heal      : distinct tips=1  heights=[15]  converged=True
reorg depths per node: {'n0': [], 'n1': [], 'n2': [], 'n3': [], 'n4': [], 'n5': [], 'n6': [2], 'n7': [2], 'n8': [2], 'n9': [2], 'n10': [2], 'n11': [2]}
== Part C: gossip, partition, heal ==
connected phase : tips=1
partitioned     : distinct tips=2  heights=[9, 12]
after heal      : distinct tips=1  heights=[17]  converged=True
reorg depths per node: {'n0': [1, 4], 'n1': [1, 4], 'n2': [4], 'n3': [4], 'n4': [4], 'n5': [4], 'n6': [1], 'n7': [], 'n8': [], 'n9': [], 'n10': [], 'n11': []}
```
**TODO:** plot the histogram from `stats.intervals` (matplotlib) and the slashing curve (offenders vs loss, saturating at 32 ETH near 1/3 of stake). Run gossip with 3 different seeds yourself.
**Explanations:** median/mean 0.693 and memorylessness; why 1/sqrt(N) justifies a long retarget window; why strictly > 2/3; why the same offence costs 12x more when correlated; why Casper stalls (CP) and the leak restores liveness; why equal-height tips after healing are a legitimate tie; probabilistic finality (confirmed txs return to the mempool).
