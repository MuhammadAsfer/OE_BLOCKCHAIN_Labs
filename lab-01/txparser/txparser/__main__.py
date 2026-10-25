import sys

from .tx import parse_transaction


def main():
    hex_in = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read()
    tx = parse_transaction(hex_in)
    print(f"txid      : {tx.txid}")
    print(f"wtxid     : {tx.wtxid}")
    print(f"version   : {tx.version}   locktime: {tx.locktime}   segwit: {tx.segwit}")
    print(f"size      : {tx.size}   stripped: {tx.stripped_size}   weight: {tx.weight}   vsize: {tx.vsize}")
    for n, i in enumerate(tx.inputs):
        kind = " (coinbase)" if i.is_coinbase else ""
        print(f"input  {n}  : {i.prev_txid}:{i.vout}{kind}  sequence=0x{i.sequence:08x}")
        if tx.witnesses and tx.witnesses[n]:
            print(f"  witness : {len(tx.witnesses[n])} items, sizes {[len(x) for x in tx.witnesses[n]]}")
    for n, o in enumerate(tx.outputs):
        print(f"output {n}  : {o.value} sat = {o.value / 1e8:.8f} BTC  {o.type}  {o.asm}")
        a = o.address()
        if a:
            print(f"  address : {a}")
    print("fee       : unknown (needs the values of the spent outputs)")


if __name__ == "__main__":
    try:
        main()
    except ValueError as e:
        sys.exit(f"error: {e}")
