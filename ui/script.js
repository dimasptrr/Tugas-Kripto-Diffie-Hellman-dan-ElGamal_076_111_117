"use strict";

const $ = id => document.getElementById(id);

async function api(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {})
  });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || "terjadi kesalahan");
  return j;
}

function galat(prefix, msg) {
  const e = $(prefix + "-err");
  e.textContent = msg || "";
  e.classList.toggle("tampil", !!msg);
}

async function jalan(btn, prefix, fn) {
  galat(prefix, "");
  btn.disabled = true;
  try {
    await fn();
  } catch (e) {
    galat(prefix, e.message);
  } finally {
    btn.disabled = false;
  }
}

function val(id) {
  return $(id).value.trim();
}

/* ==========================================
   Tab Navigasi
   ========================================== */
document.querySelectorAll("#nav button").forEach(b => {
  b.addEventListener("click", () => {
    document.querySelectorAll("#nav button").forEach(x => x.setAttribute("aria-selected", x === b));
    document.querySelectorAll("section").forEach(s => s.classList.toggle("aktif", s.id === b.dataset.tab));
  });
});

/* ==========================================
   1. Parameter & Kunci
   ========================================== */
$("s-go").addEventListener("click", () => jalan($("s-go"), "s", async () => {
  const r = await api("/api/setup", { bits: +val("s-bits"), seed: val("s-seed") || "20261026" });
  $("o-p").textContent = r.p;
  $("o-q").textContent = r.q;
  $("o-g").textContent = r.g;
  $("o-h").textContent = r.h;
  $("o-y").textContent = r.y;
  $("o-log").textContent = r.log;
  $("s-out").style.display = "block";
}));

/* ==========================================
   2. Diffie-Hellman & MITM
   ========================================== */
function isiDH(p, g, a, b) {
  $("dh-out").style.display = "none";
  $("dh-p").value = p;
  $("dh-g").value = g;
  $("dh-a").value = a;
  $("dh-b").value = b;
}

$("dh-toy").addEventListener("click", () => isiDH(23, 5, 6, 15));

$("dh-rand").addEventListener("click", () => jalan($("dh-rand"), "dh", async () => {
  const r = await api("/api/acak", { bits: 64 });
  isiDH(r.p, r.g, r.a, r.b);
}));

$("dh-go").addEventListener("click", () => jalan($("dh-go"), "dh", async () => {
  const q = { p: val("dh-p"), g: val("dh-g"), a: val("dh-a"), b: val("dh-b") };
  const r = await api("/api/dh", q);
  $("dh-oa").textContent = q.a;
  $("dh-ob").textContent = q.b;
  $("dh-oA").textContent = r.A;
  $("dh-oB").textContent = r.B;
  $("dh-pA").textContent = r.A;
  $("dh-pB").textContent = r.B;
  $("dh-opg").textContent = "p = " + q.p + ", g = " + q.g;
  $("dh-oK1").textContent = r.K1;
  $("dh-oK2").textContent = r.K2;

  const h = $("dh-hasil");
  h.className = "hasil " + (r.sama ? "ok" : "bad");
  h.textContent = r.sama
    ? "K = K'. Kunci sesi sama di kedua sisi, tanpa pernah dikirim."
    : "K tidak sama (seharusnya tidak terjadi).";

  $("dh-prim").textContent = r.prim === null
    ? "Pemeriksaan akar primitif dilewati karena p besar."
    : (r.prim ? "g adalah akar primitif mod p." : "Perhatian: g bukan akar primitif mod p, ruang kunci menyempit.");

  $("dh-out").style.display = "block";
}));

$("mitm-go").addEventListener("click", () => jalan($("mitm-go"), "dh", async () => {
  const r = await api("/api/mitm");
  const p = $("mitm-out");
  p.textContent = r.log;
  p.style.display = "block";
}));

/* ==========================================
   3. ElGamal & Sifat Homomorfik
   ========================================== */
function isiEG(p, g, x, k, m) {
  $("eg-out").style.display = "none";
  $("ho-out").style.display = "none";
  $("eg-p").value = p;
  $("eg-g").value = g;
  $("eg-x").value = x;
  $("eg-k").value = k;
  $("eg-m").value = m;
}

$("eg-toy").addEventListener("click", () => isiEG(2579, 2, 765, 853, 1299));

$("eg-rand").addEventListener("click", () => jalan($("eg-rand"), "eg", async () => {
  const r = await api("/api/acak", { bits: 64 });
  isiEG(r.p, r.g, r.x, "", r.m);
}));

$("eg-go").addEventListener("click", () => jalan($("eg-go"), "eg", async () => {
  const r = await api("/api/elgamal", {
    p: val("eg-p"),
    g: val("eg-g"),
    x: val("eg-x"),
    k: val("eg-k"),
    m: val("eg-m")
  });
  $("eg-oy").textContent = r.y;
  $("eg-ox").textContent = val("eg-x");
  $("eg-ok").textContent = r.k;
  $("eg-oa").textContent = r.a;
  $("eg-ob").textContent = r.b;
  $("eg-oax").textContent = r.ax;
  $("eg-oinv").textContent = r.inv;
  $("eg-om1").textContent = r.m1;
  $("eg-om2").textContent = r.m2;

  const h = $("eg-hasil");
  h.className = "hasil " + (r.ok ? "ok" : "bad");
  h.textContent = r.ok
    ? "Ciphertext (a, b) = (" + r.a + ", " + r.b + "). Dekripsi mengembalikan m asli."
    : "Dekripsi tidak cocok dengan m.";

  $("eg-out").style.display = "block";
}));

$("ho-go").addEventListener("click", () => jalan($("ho-go"), "ho", async () => {
  const r = await api("/api/homo", {
    p: val("eg-p"),
    g: val("eg-g"),
    x: val("eg-x"),
    m1: val("ho-m1"),
    m2: val("ho-m2")
  });
  $("ho-c1").textContent = "(" + r.c1.join(", ") + ")";
  $("ho-c2").textContent = "(" + r.c2.join(", ") + ")";
  $("ho-c").textContent = "(" + r.c.join(", ") + ")";

  const h = $("ho-hasil");
  h.className = "hasil " + (r.ok ? "ok" : "bad");
  h.textContent = "Dekripsi hasil kali ciphertext = " + r.dec + " (m1 x m2 mod p = " + r.harapan + ")" + (r.ok ? ". Cocok." : ". Tidak cocok.");

  $("ho-out").style.display = "block";
}));

/* ==========================================
   4. E-Voting Musrenbang
   ========================================== */
const PROGRAM = [
  "Sensor Banjir IoT di Kali Surabaya",
  "Smart Traffic Light Jl. Ahmad Yani",
  "Wi-Fi Publik & CCTV Taman Kota",
  "Aplikasi Pengaduan Warga Terpadu"
];

const CONTOH = [
  ["Rina", 0],
  ["Budi", 1],
  ["Sari", 0],
  ["Joko", 3],
  ["Dewi", 0],
  ["Agus", 2],
  ["Putri", 1],
  ["Hadi", 0],
  ["Lestari", 3],
  ["Bayu", 1]
];

function barisPemilih(nama, pil) {
  const tr = document.createElement("tr");
  const tdId = document.createElement("td");
  tdId.className = "idp";

  const tdN = document.createElement("td");
  const inN = document.createElement("input");
  inN.value = nama;
  inN.maxLength = 30;
  tdN.appendChild(inN);

  const tdP = document.createElement("td");
  const sel = document.createElement("select");
  PROGRAM.forEach((t, i) => {
    const o = document.createElement("option");
    o.value = i;
    o.textContent = (i + 1) + ". " + t;
    sel.appendChild(o);
  });
  sel.value = pil;
  tdP.appendChild(sel);

  const tdX = document.createElement("td");
  const bx = document.createElement("button");
  bx.className = "sekunder";
  bx.textContent = "Hapus";
  bx.addEventListener("click", () => {
    tr.remove();
    nomori();
  });
  tdX.appendChild(bx);

  tr.append(tdId, tdN, tdP, tdX);
  return tr;
}

function nomori() {
  [...$("v-body").children].forEach((tr, i) => {
    tr.querySelector(".idp").textContent = "P" + String(i + 1).padStart(2, "0");
  });
}

function resetContoh() {
  $("v-body").innerHTML = "";
  CONTOH.forEach(c => $("v-body").appendChild(barisPemilih(c[0], c[1])));
  nomori();
}

$("v-add").addEventListener("click", () => {
  if ($("v-body").children.length >= 50) return;
  $("v-body").appendChild(barisPemilih("Warga", 0));
  nomori();
});

$("v-reset").addEventListener("click", resetContoh);
resetContoh();

$("v-go").addEventListener("click", () => jalan($("v-go"), "v", async () => {
  const pemilih = [...$("v-body").children].map(tr => ({
    nama: tr.querySelector("input").value,
    pilihan: +tr.querySelector("select").value
  }));

  const r = await api("/api/vote", { pemilih, coba_ganda: $("v-ganda").checked });
  const maks = Math.max(...r.hasil);

  $("v-ringkas").textContent = r.sah + " suara sah, " + r.ditolak + " percobaan suara ganda ditolak. Server tidak pernah melihat pilihan individu.";

  const box = $("v-bars");
  box.innerHTML = "";
  r.program.forEach((nama, i) => {
    const d = document.createElement("div");
    d.className = "bar" + (r.hasil[i] === maks && maks > 0 ? " menang" : "");

    const a = document.createElement("div");
    a.className = "nama";
    a.textContent = nama;

    const t = document.createElement("div");
    t.className = "trek";
    const f = document.createElement("div");
    f.className = "isi";
    f.style.width = (maks ? r.hasil[i] / maks * 100 : 0) + "%";
    t.appendChild(f);

    const n = document.createElement("div");
    n.className = "n";
    n.textContent = r.hasil[i];

    d.append(a, t, n);
    box.appendChild(d);
  });

  const au = $("v-audit");
  au.innerHTML = "";
  r.audit.forEach(x => {
    const s = document.createElement("span");
    s.className = x.ok ? "y" : "n";
    s.textContent = (x.ok ? "Lolos: " : "Gagal: ") + x.teks;
    au.appendChild(s);
  });

  $("v-log").textContent = r.log;
  $("v-hasilkartu").style.display = "block";
  $("v-hasilkartu").scrollIntoView({ behavior: "smooth", block: "start" });
}));
