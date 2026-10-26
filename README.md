# E-Voting Musrenbang Surabaya — Diffie-Hellman & ElGamal

Implementasi sistem pemungutan suara elektronik (*e-voting*) Musrenbang Warga Surabaya berbasis kriptografi modern menggunakan protokol **Diffie-Hellman Key Exchange** dan **Algoritma Asimetris ElGamal**.

Seluruh algoritma kriptografi diimplementasikan secara **murni dari dasar (from scratch)** menggunakan pustaka standar Python 3 tanpa ketergantungan (*dependency*) pada pustaka kriptografi eksternal pihak ketiga.

---

## 📌 Latar Belakang & Studi Kasus

Dalam skenario Musrenbang (Musyawarah Perencanaan Pembangunan) Smart City, warga Surabaya memilih program pembangunan prioritas secara elektronik. Sistem ini menyelesaikan dua tantangan utama keamanan informasi:

| Tantangan Keamanan | Solusi Algoritma | Implementasi |
| :--- | :--- | :--- |
| **Penyadapan Jaringan (Eavesdropping)**<br>Data suara rentan disadap saat transit dari perangkat warga ke server. | **Diffie-Hellman Key Exchange** | Warga dan server menyepakati kunci sesi bersama ($K = g^{ab} \pmod p$) melalui saluran publik tanpa pernah mentransmisikan kunci itu sendiri. Kunci sesi digunakan untuk mengamankan kanal transmisi data. |
| **Kerahasiaan Pemilih & Audit Perhitungan**<br>Panitia/server dilarang mengetahui pilihan spesifik tiap individu, namun total suara akhir harus dapat dihitung dengan valid dan dapat diaudit. | **ElGamal Homomorfik Multiplikatif (Exponential ElGamal)** | Surat suara dienkripsi menggunakan kunci publik panitia. Server mengalikan semua *ciphertext* suara pemilih, kemudian melakukan dekripsi satu kali saja di akhir perhitungan. Hasil akhir terbuka tanpa pernah membuka suara individu. |

---

## ✨ Fitur Utama

1. **Fondasi Matematika Mandiri**:
   - Pembangkit bilangan acak semu (PRNG *xorshift64\**).
   - Eksponensiasi modulo cepat (*Square-and-Multiply*).
   - Algoritma Euclid Diperluas (EGCD) dan invers perkalian modulo.
   - Uji primalitas Miller-Rabin probabilistik.
   - Pembangkitan prima aman (*safe prime*) $p = 2q + 1$.
   - Pencarian akar primitif dan verifikasi generator subgrup $h = g^2$.

2. **Pertukaran Kunci Diffie-Hellman**:
   - Simulasi pertukaran parameter publik dan privat.
   - Kanal komunikasi aman terenkripsi berbasis kunci simetris hasil kesepakatan DH.
   - Demonstrasi serangan *Man-in-the-Middle* (MITM) beserta mekanisme deteksi dan pertahanannya.

3. **Enkripsi & Sifat Homomorfik ElGamal**:
   - Pembuatan pasangan kunci (*public* & *private key*).
   - Enkripsi probabilistik (dua pesan yang sama menghasilkan ciphertext berbeda).
   - Pembuktian sifat homomorfik: $D(E(m_1) \times E(m_2)) = m_1 \times m_2 \pmod p$.
   - Enkripsi eksponensial suara untuk tabulasi otomatis tanpa membuka pilihan individual.

4. **Sistem E-Voting Terpadu**:
   - Simulasi pemungutan suara warga dengan pilihan program pembangunan riil kota Surabaya.
   - Deteksi dan pencegahan suara ganda (*double voting prevention*).
   - Tabulasi suara otomatis dan lencana audit integritas data.

5. **Antarmuka Ganda (CLI & Web UI)**:
   - Menu berbasis terminal untuk demo matematika, langkah per langkah, dan uji unit.
   - Antarmuka web modern dan responsif untuk simulasi interaktif di peramban web (*browser*).

---

## 📁 Struktur Direktori

```text
tugas_kripto/
├── ui/                        # Antarmuka pengguna (Frontend)
│   ├── antarmuka.html         # Struktur dokumen HTML
│   ├── style.css              # Tata letak, tema warna, dan responsivitas (CSS)
│   └── script.js              # Penanganan event dan komunikasi API (JavaScript)
├── kripto_dasar.py            # Operasi matematika dasar, PRNG, prima, modulo
├── diffie_hellman.py          # Protokol Diffie-Hellman, saluran aman, simulasi MITM
├── elgamal.py                 # Enkripsi/dekripsi ElGamal, homomorfik, enkripsi suara
├── evoting.py                 # Alur pemungutan suara (persiapan, voting, tally, audit)
├── ui_web.py                  # Server HTTP lokal untuk antarmuka web
├── main.py                    # Entry point menu konsol / CLI
└── README.md                  # Dokumentasi proyek
```

---

## 🚀 Panduan Menjalankan Program

### Prasyarat
- Python 3.8 atau versi yang lebih baru (disarankan Python 3.10+).
- Peramban web modern (Chrome, Edge, Firefox, dll.).
- **Tanpa instalasi package tambahan** (hanya memerlukan Python bawaan).

---

### Cara 1: Menggunakan Antarmuka Web (UI Browser)
Metode interaktif melalui browser:

1. Buka terminal atau Command Prompt pada direktori proyek:
   ```bash
   python ui_web.py
   ```
2. Server HTTP lokal akan aktif dan membuka browser secara otomatis ke alamat:
   ```
   http://127.0.0.1:8765
   ```
3. Di dalam web, Anda dapat:
   - Mengatur parameter prima dan membangkitkan kunci panitia.
   - Melakukan uji coba pertukaran kunci Diffie-Hellman dan simulasi MITM.
   - Menguji enkripsi, dekripsi, dan sifat homomorfik ElGamal.
   - Menjalankan simulasi pemungutan suara warga dan melihat grafik hasil perolehan serta audit sistem.

---

### Cara 2: Menggunakan Menu Konsol (Terminal / CLI)
Metode berbasis teks yang memandu langkah demi langkah:

1. Jalankan perintah:
   ```bash
   python main.py
   ```
2. Pilih nomor menu yang tersedia:
   - **`1`**: Simulasi penuh studi kasus e-voting Musrenbang Surabaya.
   - **`2`**: Demo tahapan Diffie-Hellman (tersedia contoh angka kecil untuk verifikasi manual).
   - **`3`**: Demo tahapan ElGamal & pembuktian sifat homomorfik.
   - **`4`**: Demo serangan Man-in-the-Middle (MITM).
   - **`5`**: Uji unit semua modul (*unit testing* otomatis).
   - **`6`**: Membuka antarmuka web di browser.
   - **`0`**: Keluar.

---

## 🧪 Pengujian Unit (Unit Testing)

Untuk memastikan seluruh fungsi matematika dan kriptografi berjalan presisi tanpa bug, jalankan suite pengujian mandiri:

```bash
python -c "import main; main.uji_semua()"
```

Pengujian mencakup:
- Verifikasi eksponensiasi modular dan invers modulo.
- Pengujian primalitas bilangan Carmichael dan bilangan prima Mersenne ($2^{61}-1$).
- Verifikasi pencarian akar primitif dan faktorisasi.
- Uji kesepakatan kunci Diffie-Hellman ($K = K'$).
- Uji pemulihan pesan (*round-trip*) enkripsi-dekripsi ElGamal.
- Uji sifat homomorfik dan agregasi suara e-voting.
