"""
main.py  --  MENU UTAMA & INTEGRASI  [ANGGOTA 1]
=================================================
Jalankan:  python3 main.py

Studi kasus : E-Voting Musrenbang Warga Surabaya (Smart City)
              memakai Diffie-Hellman + ElGamal buatan sendiri (tanpa library).
"""
from kripto_dasar import PRNG, mod_exp, ringkas, garis
import kripto_dasar
import diffie_hellman as dh
import elgamal as eg
import evoting


def demo_dh_toy():
    garis("DEMO TAHAPAN DIFFIE-HELLMAN (angka kecil, bisa dicek manual)")
    p, g, a, b = 23, 5, 6, 15
    print("  Parameter publik : p =", p, ", g =", g)
    print("  Alice rahasia a =", a, "  -> A = g^a mod p = 5^6 mod 23 =", mod_exp(g, a, p))
    print("  Bob   rahasia b =", b, " -> B = g^b mod p = 5^15 mod 23 =", mod_exp(g, b, p))
    A, B = mod_exp(g, a, p), mod_exp(g, b, p)
    print("  Alice hitung K  = B^a mod p = 19^6 mod 23 =", mod_exp(B, a, p))
    print("  Bob   hitung K' = A^b mod p = 8^15 mod 23 =", mod_exp(A, b, p))
    print("  K = K' =", mod_exp(B, a, p), "-> kunci sesi sama tanpa pernah dikirim")
    print()
    print("  Versi angka besar (128 bit):")
    rng = PRNG(5)
    param = evoting.fase_persiapan(128, rng)
    print()
    dh.pertukaran_kunci("Alice", "Bob", param["p"], param["g"], rng, tampil=True)


def demo_elgamal_toy():
    garis("DEMO TAHAPAN ELGAMAL (angka kecil, bisa dicek manual)")
    p, g, x, k, m = 2579, 2, 765, 853, 1299
    print("  p =", p, ", g =", g, "(akar primitif)")
    print("  [1] KUNCI   privat x =", x, " -> y = g^x mod p = 2^765 mod 2579 =", mod_exp(g, x, p))
    pub = (mod_exp(g, x, p), g, p)
    print("  [2] ENKRIPSI m =", m, ", k =", k)
    ct = eg.enkripsi(pub, m, None, k=k)
    print("        a = g^k mod p       =", ct[0])
    print("        b = y^k * m mod p   =", ct[1])
    print("        ciphertext (a, b)   =", ct)
    print("  [3] DEKRIPSI m = b * a^(p-1-x) mod p =", eg.dekripsi(x, pub, ct))
    print("        cek cara Euclid (b * (a^x)^-1)       =", eg.dekripsi_invers(x, pub, ct))
    print()
    print("  Pesan yang sama dienkripsi dua kali (k beda) -> hasil beda:")
    rng = PRNG(3)
    print("   ", eg.enkripsi(pub, m, rng), "dan", eg.enkripsi(pub, m, rng))
    print()
    print("  Sifat homomorfik: E(6) x E(7) didekripsi =",
          eg.dekripsi(x, pub, eg.kali_ciphertext(eg.enkripsi(pub, 6, rng),
                                                  eg.enkripsi(pub, 7, rng), p)), "(= 6 x 7)")


def demo_mitm():
    rng = PRNG(9)
    param = evoting.fase_persiapan(64, rng)
    pub, priv = eg.buat_kunci(param["p"], param["h"], rng)
    contoh = [eg.enkripsi_suara(pub, 1, rng), eg.enkripsi_suara(pub, 0, rng)]
    print()
    dh.demo_mitm(param["p"], param["g"], rng, contoh)


def uji_semua():
    garis("UJI UNIT SEMUA MODUL")
    ok = True
    print("kripto_dasar.py (Anggota 1):")
    ok = kripto_dasar.uji() and ok
    print("diffie_hellman.py (Anggota 2):")
    ok = dh.uji() and ok
    print("elgamal.py (Anggota 3):")
    ok = eg.uji() and ok
    print("\nHASIL KESELURUHAN:", "SEMUA LULUS" if ok else "ADA YANG GAGAL")


def buka_ui():
    import ui_web
    ui_web.jalankan()


def menu():
    print()
    garis("KRIPTOGRAFI: DIFFIE-HELLMAN & ELGAMAL -- E-VOTING MUSRENBANG SURABAYA")
    print("  1. Simulasi penuh studi kasus e-voting")
    print("  2. Demo tahapan Diffie-Hellman")
    print("  3. Demo tahapan ElGamal")
    print("  4. Demo serangan Man-in-the-Middle")
    print("  5. Uji unit semua modul")
    print("  6. Buka antarmuka web (UI di browser)")
    print("  0. Keluar")
    return input("Pilih: ").strip()


def main():
    aksi = {"1": evoting.jalankan_simulasi, "2": demo_dh_toy, "3": demo_elgamal_toy,
            "4": demo_mitm, "5": uji_semua, "6": buka_ui}
    try:
        while True:
            pilihan = menu()
            if pilihan == "0":
                break
            if pilihan in aksi:
                aksi[pilihan]()
            else:
                print("Pilihan tidak dikenal.")
    except EOFError:
        pass


if __name__ == "__main__":
    main()
