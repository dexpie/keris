# Contributing to Keris

Terima kasih sudah ingin berkontribusi! Panduan singkat ini membantu Anda
mulai berkontribusi dengan mudah.

## Aturan dasar

- Gunakan bahasa **Indonesia atau Inggris** dalam kode (komentar) dan PR.
- Kode baru harus lulus `pytest` dan `ruff`.
- Keris mendukung **Python 3.9+** — hindari sintaks yang lebih baru.
- Jangan menambah dependency baru tanpa alasan yang kuat dan tanpa diskusi.
- Setiap modul baru harus memiliki docstring dan mengikuti struktur yang ada.

## Menyiapkan environment

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pip install ruff
```

## Menjalankan test & lint

```bash
pytest tests -q          # test suite
ruff check keris tests   # lint (rule F & E9)
```

## Struktur proyek

```
keris/
  __main__.py        # CLI
  core/              # http client, config, logger, utils
  modules/           # recon, discovery, scanner, plugins, auth, passive, fuzz
  payloads.py        # payload SQLi/XSS/SSRF, wordlist parameter
  report.py          # laporan markdown
  report_html.py     # laporan HTML
plugins/             # contoh plugin (Python & JSON)
tests/               # pytest + demo vuln server
```

## Alur kerja PR

1. Fork repo, buat branch: `git checkout -b fix/deskripsi-singkat`
2. Implementasi + tulis test bila relevan.
3. Jalankan `pytest tests -q` dan `ruff check keris tests`.
4. Commit dengan pesan jelas, contoh:
   `feat: tambah passive recon crt.sh`
   `fix: perbaiki konflik URL di fuzz parameter`
5. Push dan buka Pull Request ke branch `main`.

## Menambahkan kerentanan baru (scanner)

1. Tambahkan fungsi `check_*` di `keris/modules/scanner.py` yang mengembalikan
   `Finding` (atau `None`).
2. Gunakan `KerisHTTP` untuk semua request (mendukung proxy/auth/delay).
3. Integrasikan di `_run_scan_single` pada `keris/__main__.py`.
4. Tambahkan test di `tests/` (demo server bisa diperluas di
   `tests/demo_vuln_server.py`).

## Menambahkan plugin

Plugin bisa berupa file Python (`.py`) dengan fungsi `run(client, base, ctx)`
yang mengembalikan list `Finding`, atau file JSON (`.json`) deklaratif.
Lihat contoh di folder `plugins/` dan `keris/modules/plugins.py`.
