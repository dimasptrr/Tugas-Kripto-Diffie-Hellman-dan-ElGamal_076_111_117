"""
diffie_hellman.py  --  PENANGGUNG JAWAB: ANGGOTA 2
===================================================
Tahapan Diffie-Hellman Key Exchange + pemakaian kunci sesi untuk
mengamankan saluran (cipher aliran buatan sendiri) + demo serangan
Man-in-the-Middle.

Tahapan DH (sesuai slide):
  0. Parameter publik : bilangan prima p dan akar primitif g
  1. Pihak A pilih rahasia a  -> kirim  A = g^a mod p
  2. Pihak B pilih rahasia b  -> kirim  B = g^b mod p
  3. A hitung K  = B^a mod p
     B hitung K' = A^b mod p
  4. K = K' = g^(ab) mod p  -> dipakai sebagai kunci sesi simetris

TANPA import. Hanya memakai fungsi dari kripto_dasar.py (buatan sendiri).
"""
from kripto_dasar import (PRNG, MASK64, splitmix64, mod_exp, ringkas,
                          garis, bytes_ke_hex)


# ----------------------------------------------------------------------
# Tahap 1-4 : objek pihak DH
# ----------------------------------------------------------------------
class PihakDH:
    def __init__(self, nama, p, g, rng):
        self.nama = nama
        self.p = p
        self.g = g
        self._rahasia = rng.range(2, p - 2)          # tahap 1/2: pilih a (rahasia)
        self.publik = mod_exp(g, self._rahasia, p)   #            hitung g^a mod p
        self.kunci = None

    def hitung_kunci(self, publik_lawan):
        """Tahap 3: K = (publik lawan)^(rahasia sendiri) mod p."""
        # Validasi: tolak nilai publik trivial (1, p-1, di luar rentang)
        if publik_lawan < 2 or publik_lawan > self.p - 2:
            raise ValueError("nilai publik tidak valid")
        self.kunci = mod_exp(publik_lawan, self._rahasia, self.p)
        return self.kunci


def pertukaran_kunci(nama_a, nama_b, p, g, rng, tampil=False):
    """Menjalankan 4 tahap DH antara dua pihak. Mengembalikan (A, B, K)."""
    a = PihakDH(nama_a, p, g, rng)
    b = PihakDH(nama_b, p, g, rng)
    if tampil:
        print("  [1] " + a.nama + " pilih rahasia a (disimpan, TIDAK dikirim)")
        print("      " + a.nama + " kirim  A = g^a mod p = " + ringkas(a.publik))
        print("  [2] " + b.nama + " pilih rahasia b (disimpan, TIDAK dikirim)")
        print("      " + b.nama + " kirim  B = g^b mod p = " + ringkas(b.publik))
    k1 = a.hitung_kunci(b.publik)
    k2 = b.hitung_kunci(a.publik)
    if tampil:
        print("  [3] " + a.nama + " hitung K  = B^a mod p = " + ringkas(k1))
        print("      " + b.nama + " hitung K' = A^b mod p = " + ringkas(k2))
        print("  [4] K == K' ? " + ("YA, kunci sesi sama" if k1 == k2 else "TIDAK!"))
    return a, b, k1 if k1 == k2 else None


# ----------------------------------------------------------------------
# Kunci sesi -> cipher aliran sederhana (XOR dengan keystream)
# ----------------------------------------------------------------------
def lipat_kunci(K):
    """Memampatkan kunci sesi (besar) menjadi seed 64 bit."""
    s = 0x1234567890ABCDEF
    while K > 0:
        s = splitmix64(s ^ (K & MASK64))
        K >>= 64
    return s


def saluran_xor(K, data, nonce):
    """Enkripsi = dekripsi (XOR keystream). nonce harus beda tiap pesan."""
    rng = PRNG(lipat_kunci(K) ^ ((nonce * 0x9E3779B97F4A7C15) & MASK64))
    out = bytearray()
    for byte in data:
        out.append(byte ^ (rng.next64() >> 56))
    return bytes(out)


# ----------------------------------------------------------------------
# Serialisasi paket surat suara (daftar pasangan ciphertext ElGamal)
# ----------------------------------------------------------------------
def paket_ke_bytes(daftar_ct):
    bagian = []
    for (a, b) in daftar_ct:
        bagian.append(format(a, "x") + ":" + format(b, "x"))
    return "|".join(bagian).encode("utf-8")


def bytes_ke_paket(data):
    teks = data.decode("utf-8")
    hasil = []
    for item in teks.split("|"):
        a_hex, b_hex = item.split(":")
        hasil.append((int(a_hex, 16), int(b_hex, 16)))
    return hasil


# ----------------------------------------------------------------------
# Demo serangan Man-in-the-Middle terhadap DH tanpa autentikasi
# ----------------------------------------------------------------------
def demo_mitm(p, g, rng, paket_contoh):
    garis("DEMO SERANGAN MAN-IN-THE-MIDDLE", ch="-")
    pemilih = PihakDH("Pemilih", p, g, rng)
    server = PihakDH("Server", p, g, rng)
    mallory = PihakDH("Mallory", p, g, rng)
    print("  Mallory mencegat A dan B di jaringan, lalu mengirim M = g^m ke kedua pihak.")
    k_pemilih = pemilih.hitung_kunci(mallory.publik)   # pemilih kira ini dari server
    k_server = server.hitung_kunci(mallory.publik)     # server kira ini dari pemilih
    k_m1 = mallory.hitung_kunci(pemilih.publik)        # Mallory <-> Pemilih
    k_m2 = mallory.hitung_kunci(server.publik)         # Mallory <-> Server
    print("  Kunci Pemilih = Kunci Mallory(1) ? ", k_pemilih == k_m1)
    print("  Kunci Server  = Kunci Mallory(2) ? ", k_server == k_m2)
    print("  Kunci Pemilih = Kunci Server ?      ", k_pemilih == k_server,
          " -> keduanya mengira aman, padahal beda kunci")
    terkirim = saluran_xor(k_pemilih, paket_ke_bytes(paket_contoh), 99)
    dibaca = bytes_ke_paket(saluran_xor(k_m1, terkirim, 99))
    print("  Mallory berhasil membuka saluran dan membaca paket:", dibaca == paket_contoh)
    print("  TAPI isinya hanya ciphertext ElGamal (a, b). Tanpa kunci privat panitia x,")
    print("  Mallory tidak bisa tahu pilihan pemilih -> pertahanan berlapis.")
    print("  Solusi nyata: autentikasi pertukaran kunci (tanda tangan digital / sertifikat).")
    return k_pemilih != k_server


# ----------------------------------------------------------------------
# Uji unit
# ----------------------------------------------------------------------
def uji():
    hasil = []

    def cek(nama, kondisi):
        hasil.append(kondisi)
        print("  [" + ("PASS" if kondisi else "FAIL") + "] " + nama)

    # contoh buku: p=23, g=5, a=6, b=15 -> A=8, B=19, K=2
    cek("contoh p=23,g=5: A=5^6=8", mod_exp(5, 6, 23) == 8)
    cek("contoh p=23,g=5: B=5^15=19", mod_exp(5, 15, 23) == 19)
    cek("contoh p=23: K = 19^6 = 8^15 = 2",
        mod_exp(19, 6, 23) == 2 and mod_exp(8, 15, 23) == 2)
    p = 2579
    rng = PRNG(7)
    a, b, K = pertukaran_kunci("A", "B", p, 2, rng)
    cek("K == K' pada p=2579", K is not None and a.kunci == b.kunci)
    pesan = "pilihan rahasia 123".encode("utf-8")
    cek("cipher saluran: dekripsi(enkripsi(m)) = m",
        saluran_xor(K, saluran_xor(K, pesan, 5), 5) == pesan)
    cek("cipher saluran: ciphertext != plaintext", saluran_xor(K, pesan, 5) != pesan)
    cek("nonce beda -> ciphertext beda", saluran_xor(K, pesan, 5) != saluran_xor(K, pesan, 6))
    cek("serialisasi paket bolak-balik",
        bytes_ke_paket(paket_ke_bytes([(1, 2), (255, 4096)])) == [(1, 2), (255, 4096)])
    sal = False
    try:
        a.hitung_kunci(1)
    except ValueError:
        sal = True
    cek("nilai publik trivial (1) ditolak", sal)
    return all(hasil)


if __name__ == "__main__":
    print("Uji modul diffie_hellman (Anggota 2)")
    print("HASIL:", "SEMUA LULUS" if uji() else "ADA YANG GAGAL")
