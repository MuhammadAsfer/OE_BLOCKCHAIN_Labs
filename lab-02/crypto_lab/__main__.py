import sys

from . import curve, ecdsa, hdwallet, address, pqc

D = 0xC0FFEE00112233445566778899AABBCCDDEEFF00112233445566778899AABBCC
ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def part_a():
    print("== Part A: curve ==")
    print("G on curve :", curve.is_on_curve(curve.G))
    g2 = curve.double(curve.G)
    print("2G x       :", f"{g2[0]:064x}")
    print("n*G = O    :", curve.scalar_mul(curve.N - 1, curve.G) == curve.neg(curve.G))
    print("P+(-P) = O :", curve.add(curve.G, curve.neg(curve.G)) is None)
    print("ladder == double-and-add:", curve.scalar_mul(123456789, curve.G) == curve.scalar_mul_ladder(123456789, curve.G))
    print("SEC1 round trip:", curve.point_from_bytes(curve.point_to_bytes(g2)) == g2)


def part_b():
    print("== Part B: ECDSA ==")
    Q = curve.scalar_mul(D)
    print("address    :", address.private_key_to_address(D))
    z1, z2 = 0x1111, 0x2222
    r, s, rid = ecdsa.sign(D, z1)
    print("verify     :", ecdsa.verify(Q, z1, r, s))
    print("(r, n-s) also verifies:", ecdsa.verify(Q, z1, r, curve.N - s))
    print("deterministic:", ecdsa.sign(D, z1) == (r, s, rid))
    print("recover pubkey:", ecdsa.recover_public_key(z1, r, s, rid) == Q)
    k = 0xABCDEF1234567890
    r1, s1, _ = ecdsa.sign(D, z1, k)
    r2, s2, _ = ecdsa.sign(D, z2, k)
    print("identical r:", r1 == r2)
    rec = ecdsa.recover_private_key_from_nonce_reuse(z1, r1, s1, z2, s2, Q)
    print("original d :", hex(D))
    print("recovered d:", hex(rec), "-> match:", rec == D)


def part_c():
    print("== Part C: HD wallet ==")
    seed = hdwallet.mnemonic_to_seed(ABANDON)
    print("seed       :", seed.hex()[:16] + "...")
    for i in range(3):
        k, _ = hdwallet.derive_path(seed, f"m/44'/60'/0'/0/{i}")
        print(f"m/44'/60'/0'/0/{i}:", address.private_key_to_address(k))
    for p in ("correct horse", "correct horse "):
        k, _ = hdwallet.derive_path(hdwallet.mnemonic_to_seed(ABANDON, p), "m/44'/60'/0'/0/0")
        print(f"passphrase {p!r:17}:", address.private_key_to_address(k))
    pk, pc = hdwallet.derive_path(seed, "m/44'/60'/0'/0")
    ck, _ = hdwallet.derive_child(pk, pc, 1)
    rec = hdwallet.recover_parent_private_key(ck, curve.scalar_mul(pk), pc, 1)
    print("parent key recovered from child + xpub:", rec == pk)
    cpub, _ = hdwallet.derive_child_public(curve.scalar_mul(pk), pc, 1)
    print("watch-only derivation matches:", cpub == curve.scalar_mul(ck))
    try:
        hdwallet.recover_parent_private_key(ck, curve.scalar_mul(pk), pc, hdwallet.HARD + 1)
    except ValueError as e:
        print("hardened refused:", e)


def part_d():
    print("== Part D: post-quantum cost ==")
    print(f"{'scheme':20}{'pk':>6}{'sig':>6}{'tx B':>7}{'x ECDSA':>9}{'tps':>7}")
    for r in pqc.comparison_table():
        print(f"{r['scheme']:20}{r['pk']:>6}{r['sig']:>6}{r['tx_bytes']:>7}{r['ratio']:>8.1f}x{r['tps']:>7.2f}")
    print("\nExposure report:")
    for k, (v, why) in pqc.exposure_report().items():
        print(f"  {k:22}{v:10} {why}")


PARTS = {"curve": part_a, "ecdsa": part_b, "wallet": part_c, "pqc": part_d}
if __name__ == "__main__":
    for name in (sys.argv[1:] or PARTS):
        PARTS[name]()
        print()
