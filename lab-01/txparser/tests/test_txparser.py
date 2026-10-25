import pytest
from txparser.compactsize import encode_compact_size, read_compact_size
from txparser.reader import Reader
from txparser.script import classify, disassemble, segwit_address, base58check
from txparser.tx import parse_transaction
from .vectors import SAMPLE_TX, GENESIS_TX


@pytest.mark.parametrize("n,enc", [(0, "00"), (252, "fc"), (253, "fdfd00"), (65535, "fdffff"),
                                   (65536, "fe00000100"), (2**32 - 1, "feffffffff"),
                                   (2**32, "ff0000000001000000")])
def test_compact_roundtrip(n, enc):
    assert encode_compact_size(n).hex() == enc
    assert read_compact_size(bytes.fromhex(enc)) == (n, len(enc) // 2)


def test_compact_nonzero_offset_and_300():
    assert read_compact_size(b"\xaa\xaa\xfd\x2c\x01", 2) == (300, 5)


def test_reader_truncation():
    with pytest.raises(ValueError):
        Reader(b"\x01\x02").read(3)


def test_genesis():
    tx = parse_transaction(GENESIS_TX)
    assert tx.txid == "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    assert tx.inputs[0].is_coinbase and not tx.segwit
    assert tx.outputs[0].value == 50 * 10**8 and tx.outputs[0].type == "p2pk"
    assert tx.serialize() == bytes.fromhex(GENESIS_TX)


def test_segwit_sample():
    tx = parse_transaction(SAMPLE_TX)
    assert tx.segwit and tx.version == 2 and tx.locktime == 0
    assert (tx.size, tx.stripped_size, tx.weight, tx.vsize) == (222, 113, 561, 141)
    assert tx.inputs[0].sequence == 0xFFFFFFFD
    assert len(tx.witnesses[0]) == 2 and len(tx.witnesses[0][1]) == 33
    assert 70 <= len(tx.witnesses[0][0]) <= 72 and tx.witnesses[0][0][-1] == 1
    assert [o.type for o in tx.outputs] == ["p2wpkh", "p2wpkh"]
    assert [o.value for o in tx.outputs] == [10 * 10**8, 3999990000]   # 10 BTC + 39.9999 BTC
    assert tx.outputs[0].address().startswith("bcrt1q")
    assert tx.serialize() == bytes.fromhex(SAMPLE_TX)
    assert tx.txid != tx.wtxid
    assert tx.weight == 3 * tx.stripped_size + tx.size


def test_input0_offset_segwit_is_7():
    # 4 version + 2 marker/flag + 1 input count
    assert SAMPLE_TX[14 * 2 - 14 * 2:][:8] == "02000000"
    assert SAMPLE_TX[8:12] == "0001" and SAMPLE_TX[12:14] == "01"


@pytest.mark.parametrize("bad", ["", "zz", "abc", SAMPLE_TX[:-2], SAMPLE_TX + "00"])
def test_rejects_garbage(bad):
    with pytest.raises(ValueError):
        parse_transaction(bad)


def test_classify_all_types():
    h = "11" * 20
    assert classify(bytes.fromhex("76a914" + h + "88ac")) == "p2pkh"
    assert classify(bytes.fromhex("a914" + h + "87")) == "p2sh"
    assert classify(bytes.fromhex("0014" + h)) == "p2wpkh"
    assert classify(bytes.fromhex("0020" + "22" * 32)) == "p2wsh"
    assert classify(bytes.fromhex("5120" + "33" * 32)) == "p2tr"
    assert classify(bytes([33]) + b"\x02" + b"\x44" * 32 + b"\xac") == "p2pk"
    assert classify(bytes.fromhex("6a0401020304")) == "nulldata"
    assert classify(b"\x51") == "nonstandard"
    assert disassemble(bytes.fromhex("76a914" + h + "88ac")) == f"OP_DUP OP_HASH160 {h} OP_EQUALVERIFY OP_CHECKSIG"


def test_address_vectors():
    # BIP-173 test vector
    prog = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    assert segwit_address("bc", 0, prog) == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    # genesis P2PKH address
    assert base58check(b"\x00", bytes.fromhex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18")) == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
