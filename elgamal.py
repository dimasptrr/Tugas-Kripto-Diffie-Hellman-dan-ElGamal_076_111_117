"""
elgamal.py  --  PENANGGUNG JAWAB: ANGGOTA 3
============================================
Tahapan ElGamal + varian "exponential ElGamal" yang bersifat homomorfik
(dipakai untuk menghitung suara tanpa membuka suara individu).

Tahapan ElGamal (sesuai slide / buku Rinaldi Munir):
  1. Pembangkitan kunci
       p prima, g akar primitif, x privat (1 < x < p-2)
       y = g^x mod p
       kunci publik = (y, g, p)      kunci privat = x
  2. Enkripsi pesan m (0 <= m < p):
       pilih k acak (1 < k < p-2)
       a = g^k mod p
       b = y^k * m mod p
       ciphertext = (a, b)
  3. Dekripsi:
       m = b * (a^x)^(-1) mod p  =  b * a^(p-1-x) mod p

Sifat homomorfik (dipakai pada e-voting):
       (a1,b1) x (a2,b2) = (a1*a2, b1*b2)  ->  terdekripsi menjadi m1*m2
       Bila m = h^v  maka  m1*m2 = h^(v1+v2)  -> penjumlahan suara.

TANPA import. Hanya memakai kripto_dasar.py (buatan sendiri).
"""
from kripto_dasar import (PRNG, mod_exp, mod_inverse, dlog_brute, ringkas,
                          is_primitive_root, faktor_prima)


# ----------------------------------------------------------------------
# Tahap 1 : pembangkitan kunci
# ----------------------------------------------------------------------
def buat_kunci(p, g, rng):
    x = rng.range(2, p - 2)          # kunci privat
    y = mod_exp(g, x, p)             # y = g^x mod p
    publik = (y, g, p)
    return publik, x


# ----------------------------------------------------------------------
# Tahap 2 : enkripsi
# ----------------------------------------------------------------------
def enkripsi(publik, m, rng, k=None):
    y, g, p = publik
    if m < 0 or m >= p:
        raise ValueError("pesan harus 0 <= m < p")
    if k is None:
        k = rng.range(2, p - 2)      # bilangan acak BARU tiap enkripsi
    a = mod_exp(g, k, p)             # a = g^k mod p
    b = (mod_exp(y, k, p) * m) % p   # b = y^k * m mod p
    return (a, b)


# ----------------------------------------------------------------------
# Tahap 3 : dekripsi
# ----------------------------------------------------------------------
def dekripsi(privat_x, publik, ct):
    _, _, p = publik
    a, b = ct
    a_pangkat_min_x = mod_exp(a, p - 1 - privat_x, p)   # = (a^x)^-1 (Fermat)
    return (b * a_pangkat_min_x) % p


def dekripsi_invers(privat_x, publik, ct):
    """Cara kedua (cross-check): hitung a^x lalu inversnya dengan Euclid."""
    _, _, p = publik
    a, b = ct
    return (b * mod_inverse(mod_exp(a, privat_x, p), p)) % p


# ----------------------------------------------------------------------
# Exponential ElGamal (homomorfik) untuk e-voting
# ----------------------------------------------------------------------
def enkripsi_suara(publik, v, rng):
    """v = 0 atau 1 (jumlah suara).  m = g^v mod p, lalu dienkripsi."""
    _, g, p = publik
    return enkripsi(publik, mod_exp(g, v, p), rng)


def kali_ciphertext(ct1, ct2, p):
    """Penggabungan ciphertext = penjumlahan suara di balik layar."""
    return ((ct1[0] * ct2[0]) % p, (ct1[1] * ct2[1]) % p)


def hitung_total(publik, privat_x, daftar_ct, batas):
    """Gabungkan semua ciphertext -> dekripsi SEKALI -> log diskrit."""
    _, g, p = publik
    gabungan = (1, 1)
    for ct in daftar_ct:
        gabungan = kali_ciphertext(gabungan, ct, p)
    g_pangkat_total = dekripsi(privat_x, publik, gabungan)
    return dlog_brute(g, g_pangkat_total, p, batas), gabungan, g_pangkat_total


def adalah_residu_kuadrat(n, p):
    """Kriteria Euler: n QR mod p  <=>  n^((p-1)/2) = 1."""
    return mod_exp(n, (p - 1) // 2, p) == 1


# ----------------------------------------------------------------------
# Uji unit
# ----------------------------------------------------------------------
def uji():
    hasil = []

    def cek(nama, kondisi):
        hasil.append(kondisi)
        print("  [" + ("PASS" if kondisi else "FAIL") + "] " + nama)

    # Contoh buku (Stinson): p=2579, g=2, x=765, k=853, m=1299
    p, g, x = 2579, 2, 765
    y = mod_exp(g, x, p)
    cek("y = 2^765 mod 2579 = 949", y == 949)
    ct = enkripsi((y, g, p), 1299, None, k=853)
    cek("ciphertext contoh = (435, 2396)", ct == (435, 2396))
    cek("dekripsi contoh = 1299", dekripsi(x, (y, g, p), ct) == 1299)
    cek("dekripsi cara Euclid = 1299", dekripsi_invers(x, (y, g, p), ct) == 1299)

    rng = PRNG(11)
    pub, priv = buat_kunci(p, g, rng)
    ok = True
    for m in [0, 1, 2, 100, 2578]:
        if dekripsi(priv, pub, enkripsi(pub, m, rng)) != m:
            ok = False
    cek("round-trip beberapa pesan", ok)
    c1 = enkripsi(pub, 42, rng)
    c2 = enkripsi(pub, 42, rng)
    cek("pesan sama, k beda -> ciphertext beda (probabilistik)", c1 != c2)
    prod = dekripsi(priv, pub, kali_ciphertext(enkripsi(pub, 6, rng), enkripsi(pub, 7, rng), p))
    cek("homomorfik: D(E(6) x E(7)) = 42", prod == 42)

    h = mod_exp(g, 2, p)
    pub2, priv2 = buat_kunci(p, h, rng)
    cts = [enkripsi_suara(pub2, v, rng) for v in [1, 0, 1, 1, 0, 1]]
    total, _, _ = hitung_total(pub2, priv2, cts, 6)
    cek("tally homomorfik 1+0+1+1+0+1 = 4", total == 4)
    cek("semua ciphertext berupa residu kuadrat (tidak bocor)",
        all(adalah_residu_kuadrat(a, p) and adalah_residu_kuadrat(b, p) for a, b in cts))
    return all(hasil)


if __name__ == "__main__":
    print("Uji modul elgamal (Anggota 3)")
    print("HASIL:", "SEMUA LULUS" if uji() else "ADA YANG GAGAL")
