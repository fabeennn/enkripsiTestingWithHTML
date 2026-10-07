// Logika tampilan untuk Aplikasi Enkripsi Teks. Semua proses enkripsi dilakukan di backend Flask (app.py).
(() => {
  const $ = (id) => document.getElementById(id);
  const el = {
    teks: $("teks"), hitung: $("hitung"), fileTeks: $("file-teks"),
    metode: $("metode"), kunci: $("kunci"), petunjuk: $("petunjuk"),
    proses: $("proses"), galat: $("galat"),
    hasil: $("hasil"), blokKunci: $("blok-kunci"), kunciHasil: $("kunci-hasil"),
    statistik: $("statistik"), catatan: $("catatan"),
    salin: $("salin"), unduh: $("unduh"), unduhKunci: $("unduh-kunci"),
  };

  let daftar = [];

  const modeAktif = () => document.querySelector('input[name="mode"]:checked').value;
  const info = () => daftar.find((m) => m.nama === el.metode.value);
  const adalah = (nama) => el.metode.value === nama;

  function tampilkanGalat(pesan) {
    el.galat.textContent = pesan || "";
    el.galat.hidden = !pesan;
  }

  function sesuaikanForm() {
    const m = info();
    if (!m) return;
    const dekripsi = modeAktif() === "dekripsi";
    el.proses.textContent = dekripsi ? "Dekripsi" : "Enkripsi";
    el.petunjuk.textContent = m.petunjuk;

    if (adalah("One-Time Pad") && !dekripsi) {
      el.kunci.value = "";
      el.kunci.disabled = true;
      el.kunci.placeholder = "Dibuat otomatis oleh server";
    } else {
      el.kunci.disabled = false;
      el.kunci.placeholder = adalah("One-Time Pad") ? "Tempel kunci hex di sini" : "Contoh: " + m.contoh;
      if (!el.kunci.value || daftar.some((x) => x.contoh === el.kunci.value)) el.kunci.value = adalah("One-Time Pad") ? "" : m.contoh;
    }
  }

  function resetHasil() {
    el.hasil.value = "";
    el.kunciHasil.value = "";
    el.blokKunci.hidden = true;
    el.unduhKunci.hidden = true;
    el.statistik.hidden = true;
    el.catatan.hidden = true;
    el.salin.disabled = true;
    el.unduh.disabled = true;
  }

  function unduhTeks(nama, isi) {
    const url = URL.createObjectURL(new Blob([isi], { type: "text/plain;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = nama;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  async function muatMetode() {
    try {
      const res = await fetch("/api/metode");
      daftar = await res.json();
    } catch (e) {
      tampilkanGalat("Tidak bisa terhubung ke server Flask. Jalankan: python app.py");
      return;
    }
    el.metode.innerHTML = "";
    daftar.forEach((m) => el.metode.add(new Option(m.nama, m.nama)));
    sesuaikanForm();
  }

  async function proses() {
    tampilkanGalat("");
    if (!el.teks.value.trim()) {
      tampilkanGalat("Isi teks dulu sebelum diproses.");
      el.teks.focus();
      return;
    }
    el.proses.disabled = true;
    const dekripsi = modeAktif() === "dekripsi";
    try {
      const res = await fetch("/api/proses", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          teks: el.teks.value,
          metode: el.metode.value,
          mode: modeAktif(),
          kunci: el.kunci.value,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Terjadi kesalahan");

      el.hasil.value = data.hasil;
      el.salin.disabled = false;
      el.unduh.disabled = false;

      const punyaKunci = !!data.kunci;
      el.blokKunci.hidden = !punyaKunci;
      el.unduhKunci.hidden = !punyaKunci;
      el.kunciHasil.value = punyaKunci ? data.kunci : "";

      el.statistik.textContent = `${data.durasi_ms} ms | ${data.ukuran_input} byte masuk, ${data.ukuran_output} byte keluar`;
      el.statistik.hidden = false;
      el.catatan.hidden = !(info().klasik && !dekripsi);
    } catch (e) {
      resetHasil();
      tampilkanGalat(e.message);
    } finally {
      el.proses.disabled = false;
    }
  }

  el.metode.addEventListener("change", () => { el.kunci.value = ""; sesuaikanForm(); resetHasil(); tampilkanGalat(""); });
  document.querySelectorAll('input[name="mode"]').forEach((r) =>
    r.addEventListener("change", () => { sesuaikanForm(); resetHasil(); tampilkanGalat(""); }));

  el.teks.addEventListener("input", () => {
    el.hitung.textContent = `${el.teks.value.length} karakter`;
  });

  el.fileTeks.addEventListener("change", async () => {
    const f = el.fileTeks.files[0];
    if (!f) return;
    el.teks.value = await f.text();
    el.teks.dispatchEvent(new Event("input"));
    el.fileTeks.value = "";
  });

  el.proses.addEventListener("click", proses);

  el.salin.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(el.hasil.value);
      const awal = el.salin.textContent;
      el.salin.textContent = "Tersalin!";
      setTimeout(() => (el.salin.textContent = awal), 1200);
    } catch (e) {
      el.hasil.select();
    }
  });

  el.unduh.addEventListener("click", () => {
    const nama = modeAktif() === "dekripsi" ? "hasil_plaintext.txt" : "hasil_ciphertext.txt";
    unduhTeks(nama, el.hasil.value);
  });

  el.unduhKunci.addEventListener("click", () => unduhTeks("kunci_otp.txt", el.kunciHasil.value));

  muatMetode();
})();
