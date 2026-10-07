# -*- coding: utf-8 -*-
"""
Backend Flask untuk Aplikasi Enkripsi Teks.
Metode: Caesar, Vigenere, Playfair, Hill, One-Time Pad, Stream Cipher (RC4).

Jalankan:
    pip install -r requirements.txt
    python app.py
Lalu buka http://127.0.0.1:5000
"""
import math
import os
import secrets
import string
import time

from flask import Flask, jsonify, request, send_from_directory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)

ALFABET = string.ascii_uppercase


def bersihkan(teks):
    """Ubah ke huruf besar dan buang semua karakter selain A-Z."""
    return "".join(ch for ch in teks.upper() if ch in ALFABET)


# ---------- Caesar ----------
def _caesar(teks, kunci, arah):
    try:
        k = int(str(kunci).strip()) % 26
    except ValueError:
        raise ValueError("Kunci Caesar harus berupa bilangan bulat, misalnya 3")
    return "".join(ALFABET[(ALFABET.index(ch) + arah * k) % 26] for ch in bersihkan(teks))


def caesar_enkripsi(teks, kunci):
    return _caesar(teks, kunci, 1), str(kunci).strip()


def caesar_dekripsi(teks, kunci):
    return _caesar(teks, kunci, -1)


# ---------- Vigenere ----------
def _vigenere(teks, kunci, arah):
    kunci = bersihkan(kunci)
    if not kunci:
        raise ValueError("Kunci Vigenere harus berisi minimal 1 huruf")
    hasil = []
    for i, ch in enumerate(bersihkan(teks)):
        k = ALFABET.index(kunci[i % len(kunci)])
        hasil.append(ALFABET[(ALFABET.index(ch) + arah * k) % 26])
    return "".join(hasil)


def vigenere_enkripsi(teks, kunci):
    return _vigenere(teks, kunci, 1), kunci


def vigenere_dekripsi(teks, kunci):
    return _vigenere(teks, kunci, -1)


# ---------- Playfair ----------
def _tabel_playfair(kunci):
    kunci = bersihkan(kunci).replace("J", "I")
    if not kunci:
        raise ValueError("Kunci Playfair harus berisi minimal 1 huruf")
    urut = []
    for ch in kunci + ALFABET.replace("J", ""):
        if ch not in urut:
            urut.append(ch)
    posisi = {ch: divmod(i, 5) for i, ch in enumerate(urut)}
    return urut, posisi


def _pasangan_playfair(teks):
    teks = bersihkan(teks).replace("J", "I")
    hasil, i = [], 0
    while i < len(teks):
        a = teks[i]
        b = teks[i + 1] if i + 1 < len(teks) else None
        if b is None or a == b:
            hasil.append(a + "X")  # sisipkan X untuk huruf kembar / sisa akhir
            i += 1
        else:
            hasil.append(a + b)
            i += 2
    return hasil


def _playfair_proses(pasangan, kunci, arah):
    urut, posisi = _tabel_playfair(kunci)
    hasil = []
    for p in pasangan:
        (r1, c1), (r2, c2) = posisi[p[0]], posisi[p[1]]
        if r1 == r2:  # satu baris
            a = urut[r1 * 5 + (c1 + arah) % 5]
            b = urut[r2 * 5 + (c2 + arah) % 5]
        elif c1 == c2:  # satu kolom
            a = urut[((r1 + arah) % 5) * 5 + c1]
            b = urut[((r2 + arah) % 5) * 5 + c2]
        else:  # persegi panjang
            a = urut[r1 * 5 + c2]
            b = urut[r2 * 5 + c1]
        hasil.append(a + b)
    return "".join(hasil)


def playfair_enkripsi(teks, kunci):
    return _playfair_proses(_pasangan_playfair(teks), kunci, 1), kunci


def playfair_dekripsi(teks, kunci):
    t = bersihkan(teks).replace("J", "I")
    if len(t) % 2 != 0:
        raise ValueError("Ciphertext Playfair harus berpanjang genap")
    return _playfair_proses([t[i:i + 2] for i in range(0, len(t), 2)], kunci, -1)


# ---------- Hill ----------
def _minor(M, i, j):
    return [r[:j] + r[j + 1:] for k, r in enumerate(M) if k != i]


def _det(M):
    n = len(M)
    if n == 1:
        return M[0][0]
    if n == 2:
        return M[0][0] * M[1][1] - M[0][1] * M[1][0]
    return sum(((-1) ** j) * M[0][j] * _det(_minor(M, 0, j)) for j in range(n))


def _matriks_kunci(kunci):
    k = bersihkan(kunci)
    n = int(math.isqrt(len(k)))
    if n not in (2, 3) or n * n != len(k):
        raise ValueError("Kunci Hill harus 4 huruf (matriks 2x2) atau 9 huruf (matriks 3x3)")
    M = [[ALFABET.index(k[i * n + j]) for j in range(n)] for i in range(n)]
    if math.gcd(_det(M) % 26, 26) != 1:
        raise ValueError("Matriks kunci tidak punya invers mod 26, pilih kunci lain (contoh: HILL)")
    return M


def _invers_mod26(M):
    n = len(M)
    d_inv = pow(_det(M) % 26, -1, 26)
    kof = [[((-1) ** (i + j)) * _det(_minor(M, i, j)) for j in range(n)] for i in range(n)]
    return [[(d_inv * kof[j][i]) % 26 for j in range(n)] for i in range(n)]


def _hill_proses(teks, M):
    n = len(M)
    angka = [ALFABET.index(ch) for ch in teks]
    hasil = []
    for i in range(0, len(angka), n):
        blok = angka[i:i + n]
        for r in range(n):
            hasil.append(ALFABET[sum(M[r][c] * blok[c] for c in range(n)) % 26])
    return "".join(hasil)


def hill_enkripsi(teks, kunci):
    M = _matriks_kunci(kunci)
    n = len(M)
    t = bersihkan(teks)
    t += "X" * (-len(t) % n)  # padding agar kelipatan ukuran blok
    return _hill_proses(t, M), kunci


def hill_dekripsi(teks, kunci):
    M = _matriks_kunci(kunci)
    t = bersihkan(teks)
    if len(t) % len(M) != 0:
        raise ValueError("Panjang ciphertext Hill harus kelipatan ukuran matriks")
    return _hill_proses(t, _invers_mod26(M))


# ---------- Byte-based: OTP dan RC4 ----------
def xor_bytes(a, b):
    if len(a) != len(b):
        raise ValueError("Panjang byte harus sama")
    return bytes(x ^ y for x, y in zip(a, b))


def otp_enkripsi(teks, kunci=""):
    data = teks.encode("utf-8")
    pad = secrets.token_bytes(len(data))  # kunci acak sepanjang pesan
    return xor_bytes(data, pad).hex(), pad.hex()


def otp_dekripsi(teks_hex, kunci_hex):
    try:
        c = bytes.fromhex("".join(teks_hex.split()))
        k = bytes.fromhex("".join(kunci_hex.split()))
    except ValueError:
        raise ValueError("Ciphertext dan kunci OTP harus berupa teks hex")
    if len(c) != len(k):
        raise ValueError(f"Panjang kunci ({len(k)} byte) harus sama dengan ciphertext ({len(c)} byte)")
    return xor_bytes(c, k).decode("utf-8", errors="replace")


def _rc4_keystream(kunci_bytes, n):
    S = list(range(256))
    j = 0
    for i in range(256):  # KSA
        j = (j + S[i] + kunci_bytes[i % len(kunci_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray(n)
    for t in range(n):  # PRGA
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out[t] = S[(S[i] + S[j]) % 256]
    return bytes(out)


def _kunci_rc4(kunci):
    kb = kunci.encode("utf-8")
    if not kb:
        raise ValueError("Kunci stream cipher tidak boleh kosong")
    if len(kb) > 256:
        raise ValueError("Kunci stream cipher maksimal 256 byte")
    return kb


def stream_enkripsi(teks, kunci):
    data = teks.encode("utf-8")
    return xor_bytes(data, _rc4_keystream(_kunci_rc4(kunci), len(data))).hex(), kunci


def stream_dekripsi(teks_hex, kunci):
    try:
        c = bytes.fromhex("".join(teks_hex.split()))
    except ValueError:
        raise ValueError("Ciphertext stream cipher harus berupa teks hex")
    return xor_bytes(c, _rc4_keystream(_kunci_rc4(kunci), len(c))).decode("utf-8", errors="replace")


# nama: (fungsi enkripsi, fungsi dekripsi, petunjuk kunci, contoh kunci)
METODE = {
    "Caesar": (caesar_enkripsi, caesar_dekripsi, "Bilangan bulat (geseran)", "3"),
    "Vigenere": (vigenere_enkripsi, vigenere_dekripsi, "Kata kunci (huruf)", "KUNCI"),
    "Playfair": (playfair_enkripsi, playfair_dekripsi, "Kata kunci (huruf)", "MONARCHY"),
    "Hill": (hill_enkripsi, hill_dekripsi, "4 huruf (2x2) atau 9 huruf (3x3)", "HILL"),
    "One-Time Pad": (otp_enkripsi, otp_dekripsi,
                     "Enkripsi: kosongkan (dibuat otomatis). Dekripsi: isi kunci hex", ""),
    "Stream Cipher (RC4)": (stream_enkripsi, stream_dekripsi, "Kata kunci (teks bebas)", "rahasia"),
}

KLASIK = {"Caesar", "Vigenere", "Playfair", "Hill"}


# ---------- Route ----------
@app.get("/")
def halaman():
    return send_from_directory(BASE_DIR, "otp-lab.html")


@app.get("/otp-lab.css")
def css():
    return send_from_directory(BASE_DIR, "otp-lab.css")


@app.get("/app.js")
def js():
    return send_from_directory(BASE_DIR, "app.js")


@app.get("/api/metode")
def daftar_metode():
    return jsonify([
        {"nama": nama, "petunjuk": petunjuk, "contoh": contoh, "klasik": nama in KLASIK}
        for nama, (_, _, petunjuk, contoh) in METODE.items()
    ])


@app.post("/api/proses")
def proses():
    data = request.get_json(silent=True) or {}
    teks = data.get("teks", "")
    metode = data.get("metode", "")
    mode = data.get("mode", "enkripsi")
    kunci = data.get("kunci", "")

    if metode not in METODE:
        return jsonify(error="Metode tidak dikenal"), 400
    if not str(teks).strip():
        return jsonify(error="Teks tidak boleh kosong"), 400

    enc, dec, _, _ = METODE[metode]
    try:
        t0 = time.perf_counter()
        if mode == "dekripsi":
            hasil = dec(str(teks).strip(), kunci)
            kunci_pakai = None
        else:
            hasil, kunci_pakai = enc(teks, kunci)
        durasi = (time.perf_counter() - t0) * 1000
    except ValueError as e:
        return jsonify(error=str(e)), 400

    return jsonify(
        hasil=hasil,
        kunci=kunci_pakai if metode == "One-Time Pad" else None,
        durasi_ms=round(durasi, 3),
        ukuran_input=len(str(teks).encode("utf-8")),
        ukuran_output=len(hasil.encode("utf-8")),
    )


if __name__ == "__main__":
    app.run(debug=True)
