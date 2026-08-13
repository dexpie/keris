# Security Policy

## Reporting a Vulnerability

Keris adalah tool keamanan *open source*. Kami menghargai laporan yang
bertanggung jawab. Jika Anda menemukan kerentanan di **kode Keris** (bukan di
target scan), tolong laporkan secara privat.

### Cara melapor

1. **Jangan** membuka issue publik untuk kerentanan yang aktif dieksploitasi.
2. Kirim detail ke email keamanan proyek ini (lihat `README.md` bagian
   Kontak / lihat halaman repositori) dengan subjek
   `[Security] <ringkasan singkat>`.
3. Sertakan:
   - Versi Keris (`keris --version`)
   - Lingkungan (OS, Python)
   - Langkah reproduksi minimal
   - Dampak potensial
   - (Opsional) saran perbaikan / patch

### Proses

- Kami akan membalas dalam **5 hari kerja**.
- Kerentanan dikonfirmasi akan diperbaiki dalam rilis berikutnya.
- Kami akan memberikan kredit di changelog/README kecuali diminta anonim.

### Ruang lingkup yang TIDAK termasuk

Bug di **server target**, bukan di kode Keris — laporkan ke pemilik aplikasi
tersebut. Keris hanya alat; gunakan hanya pada sistem yang Anda miliki atau
memiliki izin tertulis untuk diuji.

## Responsible Use

Keris dirancang untuk pengujian keamanan resmi. Penyalahgunaan untuk akses
tanpa izin dapat melanggar hukum. Pengguna bertanggung jawab atas kepatuhan
hukum dan etika penggunaan.
