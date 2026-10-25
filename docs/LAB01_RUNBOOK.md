# Lab 01 runbook (Docker parts you must run yourself)

Use the lab's own README/scripts for exact flags; the sequence below follows the companion page.

```
docker compose up -d
docker compose exec bitcoind bitcoin-cli getblockchaininfo         # chain regtest, blocks 0
./scripts/setup.ps1                                                  # wallet lab01 + 101 blocks
docker compose exec bitcoind bitcoin-cli -rpcwallet=lab01 getbalance # 50.00000000
```
**Part A:** `listunspent`, `getbalances`, `gettxoutsetinfo` -> record txid/vout of the mature output, immature = 5000.
**Part B:** `listunspent 100`, two `getnewaddress`, change = 50 - 10 - 0.0001 = 39.9999,
`createrawtransaction` -> `signrawtransactionwithwallet` -> `decoderawtransaction` -> `sendrawtransaction` -> `-generate 1` -> `gettransaction`.
**Save the signed hex**, then:
```
cd txparser
uv run python -m txparser <SIGNED_HEX>     # compare every field with decoderawtransaction
```
Expected: size 222, stripped 113, weight 561, vsize 141, sequence 0xfffffffd, 2 witness items, two p2wpkh outputs.
**Part D:** same with ONE 10 BTC output, no change, using the block-2 coinbase. First broadcast -> error -25; retry with maxfeerate `0`;
mine; `getblock <hash> 2` -> coinbase value 90 (50 + 40 fee).
