"""
evoting.py  --  STUDI KASUS (gabungan Anggota 1, 2, 3)
=======================================================
STUDI KASUS : "SUARA AREK SUROBOYO" -- E-Voting Musrenbang Warga Surabaya
              (Smart City)

Warga memilih SATU program prioritas pembangunan kota lewat aplikasi.
Dua masalah keamanan yang harus diselesaikan:

  (1) Pilihan warga tidak boleh disadap di jaringan (HP warga <-> server TPS)
        -> DIFFIE-HELLMAN : HP warga & server menyepakati kunci sesi rahasia
           tanpa pernah mengirim kunci itu; kunci sesi memakai cipher aliran.

  (2) Pilihan warga tidak boleh diketahui siapa pun, termasuk server/admin,
      namun hasil akhir harus tetap bisa dihitung.
        -> ELGAMAL : surat suara dienkripsi dengan kunci publik panitia.
           Server hanya menyimpan ciphertext. Karena ElGamal (varian
           exponential) bersifat homomorfik, ciphertext dikalikan dulu,
           baru didekripsi SEKALI => hanya TOTAL yang terbuka, bukan
           pilihan individu.

Pembagian bagian file ini:
  - Fase 0  persiapan parameter publik     : ANGGOTA 1
  - Fase 1  pembangkitan kunci panitia     : ANGGOTA 3
  - Fase 2  pemungutan suara (DH + ElGamal): ANGGOTA 2
  - Fase 3  penghitungan & audit           : ANGGOTA 3
  (Menu & integrasi ada di main.py          : ANGGOTA 1)
"""
from kripto_dasar import (PRNG, mod_exp, is_prime, gen_safe_prime,
                          find_primitive_root, is_primitive_root,
                          ringkas, garis)
import diffie_hellman as dh
import elgamal as eg

PROGRAM = [
    "Sensor Banjir IoT di Kali Surabaya",
    "Smart Traffic Light Jl. Ahmad Yani",
    "Wi-Fi Publik & CCTV Taman Kota",
    "Aplikasi Pengaduan Warga Terpadu",
]

# (id pemilih, nama, indeks program pilihan) -- data fiktif untuk simulasi
PEMILIH = [
    ("P01", "Rina", 0), ("P02", "Budi", 1), ("P03", "Sari", 0),
    ("P04", "Joko", 3), ("P05", "Dewi", 0), ("P06", "Agus", 2),
    ("P07", "Putri", 1), ("P08", "Hadi", 0), ("P09", "Lestari", 3),
    ("P10", "Bayu", 1),
]


# ======================================================================
# FASE 0 -- Persiapan parameter publik DH/ElGamal         [ANGGOTA 1]
# ======================================================================
def fase_persiapan(bits, rng):
    garis("FASE 0: PARAMETER PUBLIK (p, g)  [Anggota 1]")
    print("Membangkitkan bilangan prima aman p = 2q + 1 sepanjang " + str(bits) + " bit ...")
    p, q = gen_safe_prime(bits, rng)
    print("  q          =", ringkas(q), "(prima: " + str(is_prime(q)) + ")")
    print("  p = 2q + 1 =", ringkas(p), "(prima: " + str(is_prime(p)) + ")")
    print("  Faktor prima dari p-1 = {2, q}  (karena p aman)")
    g = find_primitive_root(p, [2, q])
    print("  Akar primitif g =", g)
    print("    cek g^((p-1)/2) != 1 :", mod_exp(g, (p - 1) // 2, p) != 1)
    print("    cek g^((p-1)/q) != 1 :", mod_exp(g, (p - 1) // q, p) != 1)
    print("    => g membangkitkan seluruh elemen 1..p-1 :",
          is_primitive_root(g, p, [2, q]))
    # Untuk ElGamal e-voting dipakai generator subgrup orde q: h = g^2.
    h = mod_exp(g, 2, p)
    print("  Generator ElGamal h = g^2 mod p (orde q). Alasan: bila memakai g akar")
    print("    primitif langsung, simbol Legendre ciphertext membocorkan pilihan 0/1.")
    return {"p": p, "q": q, "g": g, "h": h}


# ======================================================================
# FASE 1 -- Pembangkitan kunci ElGamal panitia            [ANGGOTA 3]
# ======================================================================
def fase_kunci_panitia(param, rng):
    garis("FASE 1: KUNCI ELGAMAL PANITIA  [Anggota 3]")
    publik, privat = eg.buat_kunci(param["p"], param["h"], rng)
    print("  Kunci privat x  : DISIMPAN panitia (tidak pernah dikirim/ditampilkan)")
    print("  Kunci publik y  = h^x mod p =", ringkas(publik[0]))
    print("  Kunci publik (y, h, p) disebarkan ke semua aplikasi warga.")
    return publik, privat


# ======================================================================
# FASE 2 -- Pemungutan suara: DH + ElGamal                [ANGGOTA 2]
# ======================================================================
def fase_pemungutan(param, kunci_publik, rng, rinci_pertama=True, coba_ganda=True):
    garis("FASE 2: PEMUNGUTAN SUARA  [Anggota 2]")
    p, g = param["p"], param["g"]
    kotak_suara = {}          # id_pemilih -> daftar ciphertext (yang diterima server)
    ditolak = 0
    urutan = list(PEMILIH)
    if coba_ganda and len(PEMILIH) > 0:             # satu warga mencoba memilih dua kali
        id_g, nama_g, pil_g = PEMILIH[2] if len(PEMILIH) >= 3 else PEMILIH[0]
        urutan.append((id_g, nama_g, (pil_g + 1) % len(PROGRAM)))

    for nomor, (id_p, nama, pilihan) in enumerate(urutan, start=1):
        rinci = rinci_pertama and nomor == 1
        print("-- Sesi #" + str(nomor) + ": " + id_p + " (" + nama + ")")

        # (a) Diffie-Hellman: HP warga <-> server menyepakati kunci sesi
        hp, server, K = dh.pertukaran_kunci("HP-" + nama, "Server", p, g, rng, tampil=rinci)
        if K is None:
            print("   GAGAL: kunci sesi tidak sama")
            continue
        if not rinci:
            print("   DH: kunci sesi disepakati (K = " + ringkas(K) + ")")

        # (b) ElGamal: warga mengenkripsi surat suara (satu ciphertext per program)
        surat = []
        for j in range(len(PROGRAM)):
            v = 1 if j == pilihan else 0
            surat.append(eg.enkripsi_suara(kunci_publik, v, rng))
        if rinci:
            print("   [ElGamal] surat suara = 4 ciphertext (a,b), 1 per program;")
            print("             program ke-1 -> (a,b) = (" + ringkas(surat[0][0], 18) + ",")
            print("                                       " + ringkas(surat[0][1], 18) + ")")

        # (c) Kirim lewat saluran terenkripsi memakai kunci sesi DH
        terkirim = dh.saluran_xor(K, dh.paket_ke_bytes(surat), nonce=nomor)
        if rinci:
            print("   [Saluran] byte terkirim (hex, 24 byte pertama):",
                  dh.bytes_ke_hex(terkirim[:24]) + " ...")

        # (d) Server membuka saluran -> mendapat ciphertext ElGamal (bukan pilihan!)
        diterima = dh.bytes_ke_paket(dh.saluran_xor(server.kunci, terkirim, nonce=nomor))
        if diterima != surat:
            print("   GAGAL: paket rusak")
            continue

        # (e) Server menyimpan; satu warga hanya boleh satu suara
        if id_p in kotak_suara:
            ditolak += 1
            print("   DITOLAK: " + id_p + " sudah memilih (cegah suara ganda)")
        else:
            kotak_suara[id_p] = diterima
            print("   DITERIMA: ciphertext disimpan server. Server TIDAK tahu pilihan.")
    print("Ringkasan: " + str(len(kotak_suara)) + " suara sah, " + str(ditolak) + " ditolak.")
    return kotak_suara


# ======================================================================
# FASE 3 -- Penghitungan suara & audit                    [ANGGOTA 3]
# ======================================================================
def fase_penghitungan(param, kunci_publik, kunci_privat, kotak_suara):
    garis("FASE 3: PENGHITUNGAN & AUDIT  [Anggota 3]")
    p = param["p"]
    jumlah_pemilih = len(kotak_suara)
    hasil = []
    for j, nama_prog in enumerate(PROGRAM):
        kolom = [surat[j] for surat in kotak_suara.values()]
        total, gabungan, g_total = eg.hitung_total(kunci_publik, kunci_privat,
                                                   kolom, jumlah_pemilih)
        hasil.append(total)
        print("  Program " + str(j + 1) + " : " + nama_prog)
        print("    kalikan " + str(len(kolom)) + " ciphertext -> (A,B) = ("
              + ringkas(gabungan[0], 16) + ", " + ringkas(gabungan[1], 16) + ")")
        print("    dekripsi (A,B) -> h^total =", ringkas(g_total))
        print("    log diskrit kecil  -> total suara =", total)

    print()
    garis("HASIL AKHIR", ch="-")
    for j, nama_prog in enumerate(PROGRAM):
        print("  " + str(hasil[j]).rjust(2) + " suara | " + "#" * hasil[j] + " " + nama_prog)
    unggul = max(hasil)
    pemenang = [PROGRAM[j] for j in range(len(PROGRAM)) if hasil[j] == unggul]
    print("  PEMENANG: " + ", ".join(pemenang))

    # --- Audit 1: hitungan homomorfik == hitungan asli (data simulasi)
    asli = [0] * len(PROGRAM)
    sudah = []
    for id_p, nama, pil in PEMILIH:
        if id_p not in sudah:
            asli[pil] += 1
            sudah.append(id_p)
    print()
    print("  Audit 1 - cocok dengan pilihan sebenarnya (data simulasi):", asli == hasil)
    print("  Audit 2 - total suara = jumlah pemilih sah:", sum(hasil) == jumlah_pemilih)

    # --- Audit 3: semua ciphertext berupa residu kuadrat -> tidak ada kebocoran Legendre
    bersih = True
    for surat in kotak_suara.values():
        for (a, b) in surat:
            if not (eg.adalah_residu_kuadrat(a, p) and eg.adalah_residu_kuadrat(b, p)):
                bersih = False
    print("  Audit 3 - semua ciphertext residu kuadrat (tak bocor 0/1):", bersih)
    return hasil


# ======================================================================
# Simulasi penuh
# ======================================================================
def jalankan_simulasi(bits=128, seed=20261026):
    rng = PRNG(seed)
    param = fase_persiapan(bits, rng)
    print()
    publik, privat = fase_kunci_panitia(param, rng)
    print()
    kotak = fase_pemungutan(param, publik, rng)
    print()
    hasil = fase_penghitungan(param, publik, privat, kotak)
    return param, publik, privat, kotak, hasil
