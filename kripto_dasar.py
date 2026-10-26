"""
kripto_dasar.py  --  PENANGGUNG JAWAB: ANGGOTA 1
=================================================
Fondasi matematika untuk Diffie-Hellman & ElGamal.
Semua dibuat sendiri dari nol: TANPA import, TANPA library/framework.

Isi (sesuai materi slide "Akar Primitif dan Logaritma Diskrit"):
  1. PRNG            : pembangkit bilangan acak (xorshift64*) -- untuk DEMO
  2. mod_exp         : perpangkatan modular (square-and-multiply)
  3. egcd / mod_inverse : algoritma Euclid yang diperluas & invers modulo
  4. is_prime        : uji keprimaan Miller-Rabin
  5. gen_safe_prime  : bangkitkan bilangan prima aman p = 2q + 1
  6. is_primitive_root / find_primitive_root : akar primitif
  7. dlog_brute      : logaritma diskrit (brute force, untuk bilangan kecil)
  8. helper tampilan & konversi bytes

CATATAN: PRNG di sini hanya untuk keperluan tugas/demo. Sistem nyata wajib
memakai CSPRNG milik OS.
"""

MASK64 = (1 << 64) - 1
PRIMA_KECIL = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
               53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


# ----------------------------------------------------------------------
# 1. PRNG (xorshift64* dengan inisialisasi splitmix64)
# ----------------------------------------------------------------------
def splitmix64(x):
    x = (x + 0x9E3779B97F4A7C15) & MASK64
    z = x
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    return z ^ (z >> 31)


class PRNG:
    def __init__(self, seed=20261026):
        self.s = splitmix64(seed & MASK64)
        if self.s == 0:
            self.s = 0x9E3779B97F4A7C15

    def next64(self):
        x = self.s
        x ^= x >> 12
        x ^= (x << 25) & MASK64
        x ^= x >> 27
        self.s = x
        return (x * 0x2545F4914F6CDD1D) & MASK64

    def bits(self, n):
        """Bilangan acak dengan tepat <= n bit."""
        r = 0
        diambil = 0
        while diambil < n:
            r = (r << 64) | self.next64()
            diambil += 64
        return r >> (diambil - n)

    def range(self, lo, hi):
        """Bilangan acak bulat pada [lo, hi] (inklusif)."""
        span = hi - lo + 1
        return lo + self.bits(panjang_bit(span) + 64) % span


def panjang_bit(n):
    c = 0
    while n > 0:
        c += 1
        n >>= 1
    return c


# ----------------------------------------------------------------------
# 2. Perpangkatan modular: basis^eksp mod modulus
# ----------------------------------------------------------------------
def mod_exp(basis, eksp, modulus):
    hasil = 1
    basis %= modulus
    while eksp > 0:
        if eksp & 1:
            hasil = (hasil * basis) % modulus
        basis = (basis * basis) % modulus
        eksp >>= 1
    return hasil


# ----------------------------------------------------------------------
# 3. Euclid diperluas & invers modulo
# ----------------------------------------------------------------------
def egcd(a, b):
    """Kembalikan (g, x, y) sehingga a*x + b*y = g = gcd(a, b)."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def mod_inverse(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("invers modulo tidak ada (gcd != 1)")
    return x % m


# ----------------------------------------------------------------------
# 4. Uji keprimaan Miller-Rabin
# ----------------------------------------------------------------------
def is_prime(n, ronde=20):
    if n < 2:
        return False
    for p in PRIMA_KECIL:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in PRIMA_KECIL[:ronde]:
        x = mod_exp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        lolos = False
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                lolos = True
                break
        if not lolos:
            return False
    return True


# ----------------------------------------------------------------------
# 5. Bilangan prima aman  p = 2q + 1  (p dan q sama-sama prima)
#    Keuntungan: p-1 = 2 * q  -> faktor p-1 hanya {2, q}, sehingga
#    pencarian akar primitif sangat mudah dan aman dari serangan
#    Pohlig-Hellman.
# ----------------------------------------------------------------------
def gen_safe_prime(bits, rng):
    while True:
        q = rng.bits(bits - 1) | (1 << (bits - 2)) | 1
        p = 2 * q + 1
        cocok = True
        for sp in PRIMA_KECIL[1:]:          # saringan cepat
            if q % sp == 0 or p % sp == 0:
                cocok = False
                break
        if cocok and is_prime(q) and is_prime(p):
            return p, q


# ----------------------------------------------------------------------
# 6. Akar primitif
#    g adalah akar primitif mod p  <=>  untuk setiap faktor prima f dari
#    (p-1):  g^((p-1)/f) mod p != 1
# ----------------------------------------------------------------------
def faktor_prima(n):
    """Faktorisasi dengan trial division (hanya untuk n kecil / demo)."""
    hasil = []
    f = 2
    while f * f <= n:
        if n % f == 0:
            hasil.append(f)
            while n % f == 0:
                n //= f
        f += 1
    if n > 1:
        hasil.append(n)
    return hasil


def is_primitive_root(g, p, faktor_p_min_1):
    for f in faktor_p_min_1:
        if mod_exp(g, (p - 1) // f, p) == 1:
            return False
    return True


def find_primitive_root(p, faktor_p_min_1):
    g = 2
    while g < p:
        if is_primitive_root(g, p, faktor_p_min_1):
            return g
        g += 1
    raise ValueError("tidak ada akar primitif")


# ----------------------------------------------------------------------
# 7. Logaritma diskrit (brute force): cari t sehingga g^t = h (mod p)
#    Hanya layak untuk t kecil -- justru inilah yang membuat DH/ElGamal
#    aman: untuk p besar, tidak ada cara efisien melakukan ini.
# ----------------------------------------------------------------------
def dlog_brute(g, h, p, batas):
    nilai = 1
    for t in range(batas + 1):
        if nilai == h % p:
            return t
        nilai = (nilai * g) % p
    return None


# ----------------------------------------------------------------------
# 8. Helper tampilan & konversi
# ----------------------------------------------------------------------
def ringkas(x, maks=28):
    s = str(x)
    if len(s) <= maks:
        return s
    return s[:12] + "..." + s[-8:] + " (" + str(len(s)) + " digit)"


def int_ke_bytes(n):
    if n == 0:
        return bytes([0])
    out = []
    while n > 0:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    return bytes(out)


def bytes_ke_hex(b):
    hx = "0123456789abcdef"
    return "".join(hx[v >> 4] + hx[v & 15] for v in b)


def garis(judul="", panjang=72, ch="="):
    if judul:
        sisa = panjang - len(judul) - 2
        print(ch * 3 + " " + judul + " " + ch * (sisa - 3 if sisa > 3 else 3))
    else:
        print(ch * panjang)


# ----------------------------------------------------------------------
# Uji unit modul ini
# ----------------------------------------------------------------------
def uji():
    hasil = []

    def cek(nama, kondisi):
        hasil.append(kondisi)
        print("  [" + ("PASS" if kondisi else "FAIL") + "] " + nama)

    rng = PRNG(1)
    cek("mod_exp 2^10 mod 1000 = 24", mod_exp(2, 10, 1000) == 24)
    cek("mod_exp 7^128 mod 13 = 3", mod_exp(7, 128, 13) == 3)
    cek("egcd(240,46) = 2", egcd(240, 46)[0] == 2)
    cek("mod_inverse(3,11) = 4", mod_inverse(3, 11) == 4)
    cek("mod_inverse(17,3120) = 2753", mod_inverse(17, 3120) == 2753)
    cek("is_prime(2579) benar", is_prime(2579))
    cek("is_prime(561) salah (Carmichael)", not is_prime(561))
    cek("is_prime(2^61-1) benar", is_prime((1 << 61) - 1))
    cek("faktor_prima(2578) = [2, 1289]", faktor_prima(2578) == [2, 1289])
    cek("2 akar primitif mod 2579", is_primitive_root(2, 2579, [2, 1289]))
    cek("4 BUKAN akar primitif mod 2579", not is_primitive_root(4, 2579, [2, 1289]))
    cek("dlog: 2^t = 435 (mod 2579) -> t=?, 2^t cocok",
        mod_exp(2, dlog_brute(2, mod_exp(2, 77, 2579), 2579, 2578), 2579) == mod_exp(2, 77, 2579))
    p, q = gen_safe_prime(64, rng)
    cek("safe prime 64-bit: p=2q+1, keduanya prima", p == 2 * q + 1 and is_prime(p) and is_prime(q))
    g = find_primitive_root(p, [2, q])
    cek("akar primitif hasil pencarian valid", is_primitive_root(g, p, [2, q]))
    cek("g^(p-1) = 1 (Fermat)", mod_exp(g, p - 1, p) == 1)
    return all(hasil)


if __name__ == "__main__":
    print("Uji modul kripto_dasar (Anggota 1)")
    print("HASIL:", "SEMUA LULUS" if uji() else "ADA YANG GAGAL")
