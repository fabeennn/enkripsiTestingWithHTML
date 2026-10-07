(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  // ---------- helper DOM (semua teks lewat textContent, aman dari XSS) ----------
  function h(tag, props = {}, ...kids) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k === "style") node.setAttribute("style", v);
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (const kid of kids.flat()) {
      if (kid == null || kid === false) continue;
      node.append(kid);
    }
    return node;
  }

  async function post(path, body) {
    let res;
    try {
      res = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    } catch {
      throw new Error("Server Python belum jalan. Jalankan `python app.py` lalu muat ulang halaman.");
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "Terjadi kesalahan di server.");
    return data;
  }

  // ---------- komponen hasil ----------
  function field(label, value, { copy = true, plain = false } = {}) {
    const head = h("div", { class: "field__head" }, h("span", { class: "field__label", text: label }));
    if (copy) {
      const btn = h("button", { class: "copy", type: "button", text: "Salin" });
      btn.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(value);
          btn.textContent = "Tersalin!";
        } catch {
          btn.textContent = "Gagal";
        }
        setTimeout(() => (btn.textContent = "Salin"), 1500);
      });
      head.append(btn);
    }
    return h("div", { class: "field" }, head,
      h("div", { class: "field__value" + (plain ? " field__value--plain" : ""), text: value }));
  }

  const pill = (ok, yes, no) => h("span", { class: "pill " + (ok ? "pill--ok" : "pill--bad"), text: ok ? yes : no });
  const stat = (text) => h("span", { class: "stat", text });
  const card = (title, tone, ...kids) =>
    h("div", { class: "card" + (tone ? " card--" + tone : "") },
      title ? h("h3", { class: "card__title", text: title }) : null, ...kids);

  function errorCard(msg) {
    return card("Ups, ada yang salah", "bad", h("p", { class: "card__note", text: msg }));
  }

  const MAKS_TILE = 24;
  function tileRow(name, hex, color) {
    const bytes = hex.match(/../g) || [];
    const strip = h("div", { class: "tiles__strip" },
      bytes.slice(0, MAKS_TILE).map((b) => h("span", { class: "tile", style: `--tc:${color}`, text: b })));
    if (bytes.length > MAKS_TILE) {
      strip.append(h("span", { class: "tiles__more", text: `+${bytes.length - MAKS_TILE} byte` }));
    }
    return h("div", { class: "tiles__row" }, h("span", { class: "tiles__name", text: name }), strip);
  }
  function tiles(pesanHex, kunciHex, cipherHex) {
    return h("div", { class: "tiles", role: "group", "aria-label": "Visualisasi XOR per byte" },
      tileRow("pesan", pesanHex, "var(--blue)"),
      tileRow("⊕ kunci", kunciHex, "var(--butter)"),
      tileRow("= ciphertext", cipherHex, "var(--pink)"));
  }

  // ---------- jalankan aksi ----------
  async function jalankan(btn, out, fn) {
    btn.disabled = true;
    const label = btn.textContent;
    btn.textContent = "Memproses...";
    try {
      out.replaceChildren(...(await fn()));
    } catch (e) {
      out.replaceChildren(errorCard(e.message));
    } finally {
      btn.disabled = false;
      btn.textContent = label;
    }
  }

  // ---------- pesan bersama ----------
  const inputPesan = $("#pesan");
  const hitung = $("#hitung");
  function perbaruiHitung() {
    const v = inputPesan.value;
    const bytes = new TextEncoder().encode(v).length;
    hitung.textContent = `${[...v].length} karakter, ${bytes} byte`;
  }
  inputPesan.addEventListener("input", perbaruiHitung);
  perbaruiHitung();

  let terakhir = null; // hasil enkripsi terakhir

  // ---------- tab ----------
  const tabs = $$('[role="tab"]');
  function pilihTab(tab, fokus = false) {
    tabs.forEach((t) => {
      const aktif = t === tab;
      t.setAttribute("aria-selected", aktif);
      t.tabIndex = aktif ? 0 : -1;
      $("#" + t.getAttribute("aria-controls")).hidden = !aktif;
    });
    if (fokus) tab.focus();
  }
  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => pilihTab(tab));
    tab.addEventListener("keydown", (e) => {
      if (e.key === "ArrowRight") pilihTab(tabs[(i + 1) % tabs.length], true);
      if (e.key === "ArrowLeft") pilihTab(tabs[(i - 1 + tabs.length) % tabs.length], true);
    });
  });

  // ---------- Percobaan 1: enkripsi ----------
  $("#aksi-enkripsi").addEventListener("click", (e) =>
    jalankan(e.currentTarget, $("#out-enkripsi"), async () => {
      const d = await post("/api/enkripsi", { pesan: inputPesan.value });
      terakhir = d;
      return [
        card("Hasil enkripsi", d.sesuai ? "ok" : "bad",
          h("div", { class: "stats" }, stat(`Panjang pesan: ${d.panjang_byte} byte`),
            pill(d.sesuai, "Dekripsi sesuai", "Dekripsi tidak sesuai")),
          h("div", { style: "margin-top:.9rem" },
            field("Kunci (hex)", d.kunci_hex),
            field("Ciphertext (hex)", d.ciphertext_hex),
            field("Hasil dekripsi", d.hasil_dekripsi, { copy: false, plain: true }))),
        card("XOR per byte", null, tiles(d.pesan_hex, d.kunci_hex, d.ciphertext_hex)),
      ];
    }));

  // ---------- dekripsi manual ----------
  $("#isi-dari-enkripsi").addEventListener("click", () => {
    const out = $("#out-dekripsi");
    if (!terakhir) {
      out.replaceChildren(errorCard("Belum ada hasil enkripsi. Enkripsi dulu di tab pertama."));
      return;
    }
    $("#dek-cipher").value = terakhir.ciphertext_hex;
    $("#dek-kunci").value = terakhir.kunci_hex;
    out.replaceChildren();
  });

  $("#aksi-dekripsi").addEventListener("click", (e) =>
    jalankan(e.currentTarget, $("#out-dekripsi"), async () => {
      const d = await post("/api/dekripsi", {
        ciphertext_hex: $("#dek-cipher").value,
        kunci_hex: $("#dek-kunci").value,
      });
      return [
        card("Hasil dekripsi", d.utf8_valid ? "ok" : "bad",
          h("div", { class: "stats" }, stat(`Panjang: ${d.panjang_byte} byte`),
            pill(d.utf8_valid, "Teks UTF-8 valid", "Bukan teks UTF-8 yang valid")),
          h("div", { style: "margin-top:.9rem" },
            field("Pesan", d.hasil_teks, { copy: false, plain: true }),
            field("Hasil (hex)", d.hasil_hex)),
          d.utf8_valid ? null :
            h("p", { class: "card__note", text: "Kemungkinan kunci tidak cocok dengan ciphertext ini." })),
      ];
    }));

  // ---------- Langkah 1: tiga kali ----------
  $("#aksi-tiga").addEventListener("click", (e) =>
    jalankan(e.currentTarget, $("#out-tiga"), async () => {
      const d = await post("/api/uji/tiga-eksekusi", { pesan: inputPesan.value });
      return [
        ...d.eksekusi.map((x) =>
          card(`Eksekusi ${x.urutan}`, null,
            field("Kunci (hex)", x.kunci_hex), field("Ciphertext (hex)", x.ciphertext_hex))),
        card(null, d.semua_berbeda ? "ok" : "bad",
          pill(d.semua_berbeda, "Ketiga ciphertext berbeda", "Ada ciphertext yang sama"),
          h("p", { class: "card__note", text: "Pesannya sama, tapi kunci acak membuat ciphertext selalu lain." })),
      ];
    }));

  // ---------- Langkah 2: UTF-8 ----------
  $("#aksi-utf8").addEventListener("click", (e) =>
    jalankan(e.currentTarget, $("#out-utf8"), async () => {
      const d = await post("/api/uji/utf8", { teks: [$("#utf8-a").value, $("#utf8-b").value] });
      return d.hasil.map((x) => {
        const beda = x.panjang_byte > x.panjang_karakter;
        return card(x.teks, x.sesuai ? "ok" : "bad",
          h("div", { class: "stats" },
            stat(`${x.panjang_karakter} karakter`), stat(`${x.panjang_byte} byte`),
            pill(x.sesuai, "Dekripsi sesuai", "Dekripsi tidak sesuai")),
          beda ? h("p", { class: "card__note",
            text: `Selisih ${x.panjang_byte - x.panjang_karakter} byte, jadi kunci dibuat sepanjang ${x.panjang_byte} byte.` }) : null);
      });
    }));

  // ---------- Langkah 3: kunci pendek ----------
  $("#aksi-pendek").addEventListener("click", (e) =>
    jalankan(e.currentTarget, $("#out-pendek"), async () => {
      const d = await post("/api/uji/kunci-pendek", { pesan: inputPesan.value });
      const ditolak = d.jenis_error !== null;
      return [
        card(ditolak ? "XOR menolak kunci ini" : "Kunci diterima", ditolak ? "ok" : "bad",
          h("div", { class: "stats" }, stat(`Pesan: ${d.panjang_pesan} byte`), stat(`Kunci: ${d.panjang_kunci} byte`)),
          ditolak ? h("div", { style: "margin-top:.9rem" }, field(d.jenis_error, d.pesan_error, { copy: false, plain: true })) : null),
      ];
    }));

  // ---------- Langkah 4: kunci salah ----------
  $("#aksi-salah").addEventListener("click", (e) =>
    jalankan(e.currentTarget, $("#out-salah"), async () => {
      const d = await post("/api/uji/kunci-salah", { pesan: inputPesan.value });
      return [
        card("Dibuka dengan kunci lain", d.sama ? "bad" : "ok",
          pill(!d.sama, "Hasil tidak sama dengan pesan", "Kebetulan sama (sangat jarang)"),
          h("div", { style: "margin-top:.9rem" },
            field("Pesan asli (hex)", d.pesan_hex),
            field("Hasil salah (hex)", d.hasil_salah_hex),
            field("Hasil salah (teks)", d.hasil_salah_teks, { copy: false, plain: true }))),
      ];
    }));
})();
