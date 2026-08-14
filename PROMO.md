# PROMO — keris

Panduan ini **untuk kamu** (bukan template generik). Ide utamanya: postingan
LinkedIn/tweet yang laku itu **cerita orangnya**, bukan daftar fitur. Jadi di
bawah ini ada struktur + kalimat isian yang tinggal kamu lengkapi.

Yang wajib kamu siapkan sebelum posting:
- Screenshot dari `docs/screenshots/` (`keris_card.png`, `scan.png`)
- Link repo: `github.com/dexpie/keris`
- Satu kalimat "kenapa aku bikin ini" — itu hook yang paling penting

---

## 1. LinkedIn — postingan utama

### Yang dibutuhkan (ceklist)

- [ ] Hook personal (baris 1–3, maks 2 kalimat)
- [ ] 1–2 screenshot (card keris + output scan)
- [ ] Apa manfaatnya buat orang (bukan "38 fitur")
- [ ] CTA: repo + `pip install keris-toolkit`
- [ ] 3–5 hashtag

### Struktur yang bisa langsung kamu isi

```
[Aku buat tools ini karena] [ISI CERITA: misal waktu tes website sendiri,
bingung liat laporan pentest yang njelimet, jadi bikin yang satu perintah
selesai].

Keris — toolkit pentest web yang jalan di terminal. Kasih satu URL, dia
ngerjain semuanya: recon, discovery, vuln scan, sampai laporan. [ISI 1
CONTOH: pas aku coba ke situs sendiri, langsung ketemu X dalam Y menit].

Yang paling seru:
- [ISI 1: misal --pwn jalanin semua modul sekali jalan]
- [ISI 1: misal SSRF ketahuan lewat callback, bukan tebakan]
- [ISI 1: misal credcheck buktiin password bocor beneran bisa login]

Open source, gratis, di PyPI. Kalo mau nyoba:
https://github.com/dexpie/keris

[pip install keris-toolkit]

#cybersecurity #pentesting #opensource #python #infosec
```

Contoh versi terisi (kamu bisa ubah):

```
Aku sering bingung nerjemahin hasil scan pentest yang isinya ratusan baris.
Jadi aku bikin Keris: toolkit web pentest yang hidup di terminal. Satu URL,
dia kerjain recon sampai laporan.

Pas aku coba ke web pribadi, langsung ketemu .git yang bocor + kredensial
valid. Itu yang bikin aku yakin tools ini layak dibagi.

Fitur andalan:
- --pwn: semua modul jalan sekali jalan (hunt, exploit, brute, CVE)
- SSRF terbukti lewat callback, bukan asumsi
- credcheck: buktiin password bocor beneran bisa login

Open source & gratis: https://github.com/dexpie/keris
#cybersecurity #pentesting #opensource
```

### Tips khusus LinkedIn

- **Buka dengan "Aku"** bukan "Saya membuat sebuah tools" — orang baca cerita,
  bukan CV.
- **Posting jam kerja** (Selasa–Kamis, 08.00–11.00 atau 19.00–21.00 waktu
  setempat) lebih ramai.
- **Komentar pertama** bisa berisi 2–3 screenshot + link, biar post-nya bersih.
- Jangan pakai link di kalimat pertama — LinkedIn menekan jangkauan post yang
  langsung "jualan".

---

## 2. X / Twitter — thread

**Tweet 1 (cerita, bukan fitur):**
```
Aku bikin toolkit pentest web karena males buka 5 tools buat 1 pekerjaan.
Sekarang: satu URL masuk, recon + scan + laporan keluar.

[keris_card.png]
```

**Tweet 2 (bukti):**
```
Yang bikin aku kaget pas ngetes:
- .git bocor ketemu otomatis
- password valid kebukti bisa login (bukan nebak)
- SSRF ketahuan lewat callback

[scan.png]
```

**Tweet 3 (CTA + safety):**
```
pip install keris-toolkit
github.com/dexpie/keris

Brutal tool — selau authorized testing aja. User tanggung jawab sendiri.

#infosec #pentesting
```

---

## 3. Reddit (r/netsec / r/cybersecurity)

Format `[Project]` + jujur soal limits:

```
[Project] Keris — terminal web pentest toolkit (open source)

Aku bikin ini dari hasil ngetes situs produksi. Yang bikin beda:
- OOB SSRF (callback listener, bukan guess)
- .git dump + credential hunting terintegrasi ke scan
- credcheck: buktiin kredensial beneran bisa login
- dos --hammer (slowloris + flood paralel, authorized only)

Semua mode agresif wajib flag --authorized/--yes + banner peringatan.
PyPI: keris-toolkit | Repo: https://github.com/dexpie/keris
```

---

## 4. Daftar curated (submit sekali, ketemu lama)

Fork repo-nya, tambah satu baris `- [keris](url) - deskripsi`, buat PR:

- `awesome-hacking`
- `awesome-web-security`
- `awesome-cybersecurity` (infosecn1nja)
- dev.to / Medium / Hashnode — writeup cara pakai
- r/netsec monthly tools megathread

---

## Screenshot siap pakai

| File | Ukuran | Kegunaan |
|------|--------|----------|
| `keris_card.png` | 1200×675 | Gambar utama tweet & LinkedIn |
| `scan.png` | 3861×1480 | Potongan output scan asli |
| `banner.png` | 1179×592 | Banner peringatan brutal |

Generate ulang:
```bash
python -m keris scan http://127.0.0.1:8099 --hunt --chain --triage > scan.out 2>&1
python tools/make_screenshot.py scan.out docs/screenshots/scan.png
python tools/make_card.py
```