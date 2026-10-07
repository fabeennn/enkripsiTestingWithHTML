"""OTP Lab - backend Flask untuk simulasi One Time Pad.

Lokal:  python app.py   lalu buka http://127.0.0.1:5000
Vercel: file statis ada di folder public/, Vercel otomatis memakai variabel `app` ini.
"""
import secrets
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__, static_folder=str(BASE_DIR / "public"), static_url_path="")

MAKS_KARAKTER = 500


class InputError(Exception):
    """Kesalahan input dari pengguna (dikirim sebagai HTTP 400)."""


@app.errorhandler(InputError)
def tangani_input_error(e):
    return jsonify(error=str(e)), 400


# ---------- inti OTP (sama dengan notebook) ----------
def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("Panjang byte harus sama")
    return bytes(x ^ y for x, y in zip(a, b))


def buat_kunci(panjang: int) -> bytes:
    return secrets.token_bytes(panjang)


# ---------- helper input ----------
def baca_json() -> dict:
    return request.get_json(silent=True) or {}


def baca_teks(data: dict, kunci: str = "pesan", nama: str = "Pesan") -> str:
    nilai = data.get(kunci)
    if not isinstance(nilai, str) or not nilai:
        raise InputError(f"{nama} tidak boleh kosong.")
    if len(nilai) > MAKS_KARAKTER:
        raise InputError(f"{nama} maksimal {MAKS_KARAKTER} karakter.")
    return nilai


def baca_hex(data: dict, kunci: str, nama: str) -> bytes:
    nilai = "".join(str(data.get(kunci, "")).split())
    if not nilai:
        raise InputError(f"{nama} tidak boleh kosong.")
    try:
        return bytes.fromhex(nilai)
    except ValueError:
        raise InputError(
            f"{nama} harus berupa hex yang valid (karakter 0-9 dan a-f, jumlah digit genap)."
        )


# ---------- halaman ----------
# File yang boleh dibuka publik. Dicari di public/ dulu, lalu di folder root,
# jadi tetap jalan walaupun file terupload tidak di dalam folder public/.
FILE_PUBLIK = {
    "otp-lab.html": "text/html",
    "otp-lab.css": "text/css",
    "app.js": "text/javascript",
}
LOKASI = [BASE_DIR / "public", BASE_DIR]


def kirim_file(nama: str):
    for folder in LOKASI:
        if (folder / nama).is_file():
            return send_from_directory(folder, nama, mimetype=FILE_PUBLIK[nama])
    ada = sorted(p.name for p in BASE_DIR.iterdir() if not p.name.startswith("."))
    return (
        f"File '{nama}' tidak ditemukan di server.\n"
        f"Isi folder utama: {ada}\n"
        "Pastikan file ada di folder public/ atau di root repo dengan nama yang persis sama.",
        404,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


@app.get("/")
def index():
    return kirim_file("otp-lab.html")


@app.get("/otp-lab.html")
def halaman():
    return kirim_file("otp-lab.html")


@app.get("/otp-lab.css")
def gaya():
    return kirim_file("otp-lab.css")


@app.get("/app.js")
def skrip():
    return kirim_file("app.js")


# ---------- Percobaan 1: enkripsi + dekripsi ----------
@app.post("/api/enkripsi")
def enkripsi():
    pesan_teks = baca_teks(baca_json())
    pesan = pesan_teks.encode("utf-8")
    kunci = buat_kunci(len(pesan))
    ciphertext = xor_bytes(pesan, kunci)
    pulih = xor_bytes(ciphertext, kunci)
    return jsonify(
        panjang_byte=len(pesan),
        pesan_hex=pesan.hex(),
        kunci_hex=kunci.hex(),
        ciphertext_hex=ciphertext.hex(),
        hasil_dekripsi=pulih.decode("utf-8"),
        sesuai=pulih == pesan,
    )


# ---------- dekripsi manual ----------
@app.post("/api/dekripsi")
def dekripsi():
    data = baca_json()
    ciphertext = baca_hex(data, "ciphertext_hex", "Ciphertext")
    kunci = baca_hex(data, "kunci_hex", "Kunci")
    if len(ciphertext) != len(kunci):
        raise InputError(
            f"Panjang ciphertext ({len(ciphertext)} byte) dan kunci ({len(kunci)} byte) harus sama."
        )
    hasil = xor_bytes(ciphertext, kunci)
    try:
        teks, utf8_valid = hasil.decode("utf-8"), True
    except UnicodeDecodeError:
        teks, utf8_valid = hasil.decode("utf-8", errors="replace"), False
    return jsonify(
        panjang_byte=len(hasil),
        hasil_hex=hasil.hex(),
        hasil_teks=teks,
        utf8_valid=utf8_valid,
    )


# ---------- Langkah 1: tiga kali eksekusi ----------
@app.post("/api/uji/tiga-eksekusi")
def uji_tiga_eksekusi():
    pesan = baca_teks(baca_json()).encode("utf-8")
    hasil = []
    for i in range(1, 4):
        k = buat_kunci(len(pesan))
        c = xor_bytes(pesan, k)
        hasil.append({"urutan": i, "kunci_hex": k.hex(), "ciphertext_hex": c.hex()})
    semua_berbeda = len({h["ciphertext_hex"] for h in hasil}) == len(hasil)
    return jsonify(eksekusi=hasil, semua_berbeda=semua_berbeda)


# ---------- Langkah 2: karakter vs byte (UTF-8) ----------
@app.post("/api/uji/utf8")
def uji_utf8():
    data = baca_json()
    daftar = data.get("teks")
    if not isinstance(daftar, list) or not daftar:
        raise InputError("Kirim minimal satu teks.")
    hasil = []
    for teks in daftar[:5]:
        if not isinstance(teks, str) or not teks:
            raise InputError("Teks tidak boleh kosong.")
        if len(teks) > MAKS_KARAKTER:
            raise InputError(f"Teks maksimal {MAKS_KARAKTER} karakter.")
        b = teks.encode("utf-8")
        k = buat_kunci(len(b))
        c = xor_bytes(b, k)
        p = xor_bytes(c, k)
        hasil.append(
            {
                "teks": teks,
                "panjang_karakter": len(teks),
                "panjang_byte": len(b),
                "sesuai": p.decode("utf-8") == teks,
            }
        )
    return jsonify(hasil=hasil)


# ---------- Langkah 3: kunci terlalu pendek ----------
@app.post("/api/uji/kunci-pendek")
def uji_kunci_pendek():
    pesan = baca_teks(baca_json()).encode("utf-8")
    kunci_pendek = buat_kunci(len(pesan) - 1)
    try:
        xor_bytes(pesan, kunci_pendek)
        jenis, isi = None, None
    except ValueError as e:
        jenis, isi = "ValueError", str(e)
    return jsonify(
        panjang_pesan=len(pesan),
        panjang_kunci=len(kunci_pendek),
        jenis_error=jenis,
        pesan_error=isi,
    )


# ---------- Langkah 4: kunci salah ----------
@app.post("/api/uji/kunci-salah")
def uji_kunci_salah():
    pesan = baca_teks(baca_json()).encode("utf-8")
    kunci = buat_kunci(len(pesan))
    ciphertext = xor_bytes(pesan, kunci)
    kunci_salah = buat_kunci(len(pesan))
    hasil_salah = xor_bytes(ciphertext, kunci_salah)
    return jsonify(
        pesan_hex=pesan.hex(),
        hasil_salah_hex=hasil_salah.hex(),
        hasil_salah_teks=hasil_salah.decode("utf-8", errors="replace"),
        sama=hasil_salah == pesan,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
