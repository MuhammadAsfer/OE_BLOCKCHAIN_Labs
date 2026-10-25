import pytest
from crypto_lab import curve, ecdsa, hdwallet, address, pqc
from crypto_lab.curve import G, N, P

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def test_generator_and_2g():
    assert curve.is_on_curve(G)
    assert curve.double(G)[0] == 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5


def test_group_laws():
    assert curve.add(G, curve.neg(G)) is None
    assert curve.add(None, G) == G
    assert curve.scalar_mul(N - 1) == curve.neg(G)
    assert curve.add(curve.scalar_mul(N - 1), G) is None


@pytest.mark.parametrize("k", [1, 2, 3, 13, 2**64 + 5, N - 2])
def test_ladder_equals_double_and_add(k):
    assert curve.scalar_mul(k) == curve.scalar_mul_ladder(k)


def test_sec1():
    assert curve.point_to_bytes(G).hex() == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    for k in (1, 2, 99):
        pt = curve.scalar_mul(k)
        for comp in (True, False):
            assert curve.point_from_bytes(curve.point_to_bytes(pt, comp)) == pt
    bad = next(x for x in range(1, 50) if curve.sqrt_mod_p(x ** 3 + 7) is None)
    with pytest.raises(ValueError):
        curve.point_from_bytes(b"\x02" + bad.to_bytes(32, "big"))


def test_rfc6979_known_vector():
    import hashlib
    z = int.from_bytes(hashlib.sha256(b"Satoshi Nakamoto").digest(), "big")
    assert ecdsa.rfc6979_nonce(1, z) == 0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15


def test_sign_verify_lows_recover():
    d, z = 0xC0FFEE, 0xDEADBEEF
    Q = curve.scalar_mul(d)
    r, s, rid = ecdsa.sign(d, z)
    assert s <= N // 2 and ecdsa.verify(Q, z, r, s) and ecdsa.verify(Q, z, r, N - s)
    assert not ecdsa.verify(Q, z, r, N - s, require_low_s=True)
    assert ecdsa.sign(d, z) == (r, s, rid)
    assert ecdsa.recover_public_key(z, r, s, rid) == Q
    assert not ecdsa.verify(Q, z + 1, r, s)


@pytest.mark.parametrize("flip1", [False, True])
@pytest.mark.parametrize("flip2", [False, True])
def test_nonce_reuse_all_sign_combinations(flip1, flip2):
    d, k = 0x1234567890ABCDEF, 0xFEDCBA987654321
    Q = curve.scalar_mul(d)
    r, s1, _ = ecdsa.sign(d, 111, k)
    _, s2, _ = ecdsa.sign(d, 222, k)
    s1 = N - s1 if flip1 else s1
    s2 = N - s2 if flip2 else s2
    assert ecdsa.recover_private_key_from_nonce_reuse(111, r, s1, 222, s2, Q) == d


def test_keccak_and_not_sha3():
    import hashlib
    assert address.keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert hashlib.sha3_256(b"").digest() != address.keccak256(b"")


@pytest.mark.parametrize("a", ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                               "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"])
def test_eip55_examples(a):
    assert address.to_checksum_address(a.lower()) == a


def test_bip39_wordlist_and_mnemonic():
    assert len(hdwallet.WORDS) == 2048 and hdwallet.WORDS[0] == "abandon"
    assert hdwallet.entropy_to_mnemonic(bytes(16)) == ABANDON
    assert hdwallet.mnemonic_to_seed(ABANDON).hex().startswith("5eb00bbddcf06908")


def test_ethereum_addresses_from_abandon():
    seed = hdwallet.mnemonic_to_seed(ABANDON)
    exp = ["0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0",
           "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A"]
    for i, e in enumerate(exp):
        k, _ = hdwallet.derive_path(seed, f"m/44'/60'/0'/0/{i}")
        assert address.private_key_to_address(k) == e


def test_passphrase_changes_wallet_silently():
    a = hdwallet.derive_path(hdwallet.mnemonic_to_seed(ABANDON, "correct horse"), "m/44'/60'/0'/0/0")[0]
    b = hdwallet.derive_path(hdwallet.mnemonic_to_seed(ABANDON, "correct horse "), "m/44'/60'/0'/0/0")[0]
    assert address.private_key_to_address(a).lower().startswith("0xff0bdf99")
    assert address.private_key_to_address(b).lower().startswith("0x67da015b")


def test_xpub_leak_and_hardening():
    seed = hdwallet.mnemonic_to_seed(ABANDON)
    pk, pc = hdwallet.derive_path(seed, "m/44'/60'/0'/0")
    pub = curve.scalar_mul(pk)
    ck, _ = hdwallet.derive_child(pk, pc, 1)
    assert hdwallet.recover_parent_private_key(ck, pub, pc, 1) == pk
    assert hdwallet.derive_child_public(pub, pc, 1)[0] == curve.scalar_mul(ck)
    with pytest.raises(ValueError):
        hdwallet.recover_parent_private_key(ck, pub, pc, hdwallet.HARD + 1)
    with pytest.raises(ValueError):
        hdwallet.derive_child_public(pub, pc, hdwallet.HARD)


def test_parse_path():
    assert hdwallet.parse_path("m/44'/0/1") == [44 + 2**31, 0, 1]


def test_pqc_numbers():
    rows = {r["scheme"]: r for r in pqc.comparison_table()}
    assert rows["ML-DSA-44"]["tx_bytes"] == 3842 and round(rows["ML-DSA-44"]["ratio"], 1) == 17.9
    assert rows["FN-DSA-512"]["tx_bytes"] == 1673 and rows["SLH-DSA-128s"]["tx_bytes"] == 7998
    assert round(rows["ECDSA (secp256k1)"]["tps"], 2) == 7.75
    rep = pqc.exposure_report()
    assert rep["p2pkh_unspent"][0] == "PROTECTED" and rep["p2pk"][0] == "EXPOSED"


def test_bip84_address_vector():
    # m/84'/0'/0'/0/0 for 'abandon...about' -> bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
    import sys, hashlib
    sys.path.insert(0, "../lab-01/txparser")
    from txparser.script import segwit_address
    k, _ = hdwallet.derive_path(hdwallet.mnemonic_to_seed(ABANDON), "m/84'/0'/0'/0/0")
    try:
        hashlib.new("ripemd160")
    except ValueError:
        pytest.skip("ripemd160 unavailable in this OpenSSL build")
    h160 = hashlib.new("ripemd160", hashlib.sha256(curve.point_to_bytes(curve.scalar_mul(k))).digest()).digest()
    assert segwit_address("bc", 0, h160) == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
