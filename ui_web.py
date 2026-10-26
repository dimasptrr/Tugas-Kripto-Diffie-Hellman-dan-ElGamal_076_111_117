"""
ui_web.py  --  ANTARMUKA WEB LOKAL
===================================
Jalankan:  python ui_web.py      (atau menu 6 di main.py)
Lalu browser terbuka otomatis di  http://127.0.0.1:8765

Pembagian:
  - Server, endpoint /api/setup, /api/acak, halaman Parameter : ANGGOTA 1
  - Endpoint /api/dh, /api/mitm, halaman Diffie-Hellman       : ANGGOTA 2
  - Endpoint /api/elgamal, /api/homo, /api/vote, halaman
    ElGamal & E-Voting (antarmuka.html)                       : ANGGOTA 3

CATATAN: seluruh perhitungan kriptografi tetap memakai modul buatan sendiri
(kripto_dasar, diffie_hellman, elgamal, evoting). Lapisan UI ini hanya
memakai pustaka standar Python untuk menjalankan server HTTP lokal dan
menampilkan halaman -- bukan untuk kriptografi.
"""
import io
import json
import os
import webbrowser
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer

from kripto_dasar import (PRNG, mod_exp, mod_inverse, is_prime, gen_safe_prime,
                          find_primitive_root, is_primitive_root, faktor_prima)
import diffie_hellman as dh
import elgamal as eg
import evoting
import main as app_main

FOLDER = os.path.dirname(os.path.abspath(__file__))
STATE = {"param": None, "pub": None, "priv": None, "rng": PRNG(20261026)}


# ----------------------------------------------------------------------
# Helper
# ----------------------------------------------------------------------
def tangkap(fn, *a, **k):
    """Jalankan fungsi yang print(), kembalikan (hasil, teks_log)."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        hasil = fn(*a, **k)
    return hasil, buf.getvalue()


def angka(d, kunci, wajib=True):
    v = str(d.get(kunci, "")).strip()
    if v == "":
        if wajib:
            raise ValueError("kolom '" + kunci + "' belum diisi")
        return None
    if len(v) > 200 or not v.isdigit():
        raise ValueError("kolom '" + kunci + "' harus bilangan bulat positif")
    return int(v)


def s(x):
    return str(x)


# ----------------------------------------------------------------------
# Endpoint umum  [Anggota 1]
# ----------------------------------------------------------------------
def api_setup(d):
    bits = int(d.get("bits", 128))
    seed = int(d.get("seed", 20261026))
    if bits < 16 or bits > 192:
        raise ValueError("bit harus 16 sampai 192")
    rng = PRNG(seed)

    def kerja():
        param = evoting.fase_persiapan(bits, rng)
        print()
        pub, priv = evoting.fase_kunci_panitia(param, rng)
        return param, pub, priv

    (param, pub, priv), log = tangkap(kerja)
    STATE.update(param=param, pub=pub, priv=priv, rng=rng)
    return {"log": log, "p": s(param["p"]), "q": s(param["q"]), "g": s(param["g"]),
            "h": s(param["h"]), "y": s(pub[0]), "bits": bits}


def api_acak(d):
    bits = int(d.get("bits", 64))
    if bits < 16 or bits > 192:
        raise ValueError("bit harus 16 sampai 192")
    rng = PRNG(STATE["rng"].next64())
    p, q = gen_safe_prime(bits, rng)
    g = find_primitive_root(p, [2, q])
    return {"p": s(p), "g": s(g), "a": s(rng.range(2, p - 2)), "b": s(rng.range(2, p - 2)),
            "x": s(rng.range(2, p - 2)), "k": s(rng.range(2, p - 2)),
            "m": s(rng.range(2, p - 2)), "m1": s(rng.range(2, 1000)), "m2": s(rng.range(2, 1000))}


# ----------------------------------------------------------------------
# Diffie-Hellman & MITM  [Anggota 2]
# ----------------------------------------------------------------------
def api_dh(d):
    p, g, a, b = angka(d, "p"), angka(d, "g"), angka(d, "a"), angka(d, "b")
    galat = []
    if p < 5 or not is_prime(p):
        galat.append("p harus bilangan prima (>= 5)")
    if galat:
        raise ValueError("; ".join(galat))
    if not 2 <= g <= p - 2:
        galat.append("g harus 2 <= g <= p-2")
    if not 2 <= a <= p - 2:
        galat.append("rahasia a harus 2 <= a <= p-2")
    if not 2 <= b <= p - 2:
        galat.append("rahasia b harus 2 <= b <= p-2")
    if galat:
        raise ValueError("; ".join(galat))
    A, B = mod_exp(g, a, p), mod_exp(g, b, p)
    K1, K2 = mod_exp(B, a, p), mod_exp(A, b, p)
    prim = None
    if p < 10 ** 12:
        prim = is_primitive_root(g, p, faktor_prima(p - 1))
    return {"A": s(A), "B": s(B), "K1": s(K1), "K2": s(K2), "sama": K1 == K2, "prim": prim}


def api_mitm(d):
    _, log = tangkap(app_main.demo_mitm)
    return {"log": log}


# ----------------------------------------------------------------------
# ElGamal, Homomorfik, E-Voting  [Anggota 3]
# ----------------------------------------------------------------------
def cek_elgamal(d):
    p, g, x = angka(d, "p"), angka(d, "g"), angka(d, "x")
    if p < 5 or not is_prime(p):
        raise ValueError("p harus bilangan prima (>= 5)")
    if not 2 <= g <= p - 2:
        raise ValueError("g harus 2 <= g <= p-2")
    if not 2 <= x <= p - 2:
        raise ValueError("kunci privat x harus 2 <= x <= p-2")
    return p, g, x


def api_elgamal(d):
    p, g, x = cek_elgamal(d)
    m = angka(d, "m")
    if m >= p:
        raise ValueError("pesan m harus lebih kecil dari p")
    k = angka(d, "k", wajib=False)
    if k is None:
        k = STATE["rng"].range(2, p - 2)
    if not 2 <= k <= p - 2:
        raise ValueError("k harus 2 <= k <= p-2")
    y = mod_exp(g, x, p)
    pub = (y, g, p)
    a, b = eg.enkripsi(pub, m, None, k=k)
    m1 = eg.dekripsi(x, pub, (a, b))
    ax = mod_exp(a, x, p)
    inv = mod_inverse(ax, p)
    m2 = eg.dekripsi_invers(x, pub, (a, b))
    return {"y": s(y), "k": s(k), "a": s(a), "b": s(b), "ax": s(ax), "inv": s(inv),
            "m1": s(m1), "m2": s(m2), "ok": m1 == m and m2 == m}


def api_homo(d):
    p, g, x = cek_elgamal(d)
    m1, m2 = angka(d, "m1"), angka(d, "m2")
    if m1 >= p or m2 >= p:
        raise ValueError("m1 dan m2 harus lebih kecil dari p")
    pub = (mod_exp(g, x, p), g, p)
    rng = STATE["rng"]
    c1, c2 = eg.enkripsi(pub, m1, rng), eg.enkripsi(pub, m2, rng)
    c = eg.kali_ciphertext(c1, c2, p)
    dec = eg.dekripsi(x, pub, c)
    return {"c1": [s(c1[0]), s(c1[1])], "c2": [s(c2[0]), s(c2[1])],
            "c": [s(c[0]), s(c[1])], "dec": s(dec), "harapan": s(m1 * m2 % p),
            "ok": dec == m1 * m2 % p}


def api_vote(d):
    pemilih = d.get("pemilih", [])
    if not 1 <= len(pemilih) <= 50:
        raise ValueError("jumlah pemilih harus 1 sampai 50")
    daftar = []
    for i, v in enumerate(pemilih, start=1):
        nama = str(v.get("nama", "")).strip()[:30] or ("Warga" + str(i))
        pil = int(v.get("pilihan", 0))
        if not 0 <= pil < len(evoting.PROGRAM):
            raise ValueError("pilihan program tidak valid")
        daftar.append(("P%02d" % i, nama, pil))
    if STATE["param"] is None:
        api_setup({"bits": 128, "seed": 20261026})
    evoting.PEMILIH = daftar

    def kerja():
        kotak = evoting.fase_pemungutan(STATE["param"], STATE["pub"], STATE["rng"],
                                        coba_ganda=bool(d.get("coba_ganda", True)))
        print()
        return evoting.fase_penghitungan(STATE["param"], STATE["pub"], STATE["priv"], kotak)

    hasil, log = tangkap(kerja)
    audit = []
    for baris in log.split("\n"):
        if baris.strip().startswith("Audit"):
            audit.append({"teks": baris.strip()[:baris.strip().rfind(":")].strip(),
                          "ok": baris.strip().endswith("True")})
    ditolak = 0
    for baris in log.split("\n"):
        if "DITOLAK" in baris:
            ditolak += 1
    return {"log": log, "hasil": hasil, "program": evoting.PROGRAM, "audit": audit,
            "ditolak": ditolak, "sah": sum(hasil)}


RUTE = {"/api/setup": api_setup, "/api/acak": api_acak, "/api/dh": api_dh,
        "/api/mitm": api_mitm, "/api/elgamal": api_elgamal, "/api/homo": api_homo,
        "/api/vote": api_vote}


# ----------------------------------------------------------------------
# Server HTTP lokal  [Anggota 1]
# ----------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _kirim(self, kode, tipe, isi):
        self.send_response(kode)
        self.send_header("Content-Type", tipe)
        self.send_header("Content-Length", str(len(isi)))
        self.end_headers()
        self.wfile.write(isi)

    def do_GET(self):
        berkas = {
            "/": ("antarmuka.html", "text/html; charset=utf-8"),
            "/index.html": ("antarmuka.html", "text/html; charset=utf-8"),
            "/antarmuka.html": ("antarmuka.html", "text/html; charset=utf-8"),
            "/style.css": ("style.css", "text/css; charset=utf-8"),
            "/script.js": ("script.js", "application/javascript; charset=utf-8"),
        }
        if self.path in berkas:
            nama, tipe = berkas[self.path]
            jalur = os.path.join(FOLDER, "ui", nama)
            if not os.path.isfile(jalur):
                jalur = os.path.join(FOLDER, "web", nama)
            if not os.path.isfile(jalur):
                jalur = os.path.join(FOLDER, nama)
            if os.path.isfile(jalur):
                with open(jalur, "rb") as f:
                    self._kirim(200, tipe, f.read())
                return
        self._kirim(404, "text/plain", b"tidak ditemukan")

    def do_POST(self):
        fn = RUTE.get(self.path)
        if fn is None:
            self._kirim(404, "application/json", b"{}")
            return
        try:
            panjang = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(panjang) or b"{}")
            hasil = fn(data)
            self._kirim(200, "application/json", json.dumps(hasil).encode("utf-8"))
        except (ValueError, KeyError, TypeError) as e:
            self._kirim(400, "application/json", json.dumps({"error": str(e)}).encode("utf-8"))


def jalankan(port=8765):
    server = None
    for p in range(port, port + 11):
        try:
            server = HTTPServer(("127.0.0.1", p), Handler)
            break
        except OSError:
            continue
    if server is None:
        print("Tidak ada port kosong.")
        return
    url = "http://127.0.0.1:" + str(server.server_address[1])
    print("Antarmuka berjalan di " + url + "  (tekan Ctrl+C untuk berhenti)")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer dihentikan.")
    server.server_close()


if __name__ == "__main__":
    jalankan()
