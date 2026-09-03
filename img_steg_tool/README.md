# 🖼️ Image Steganography & Forensics Toolkit (PNG/JPG/BMP)

Tool CLI (Bash) untuk mendeteksi & mengekstrak data tersembunyi (*steganografi*)
di dalam gambar. Menggabungkan banyak tool stego (steghide, zsteg, binwalk,
exiftool, LSB analysis) menjadi satu antarmuka terstruktur — wajib untuk
challenge CTF yang menyembunyikan flag di dalam gambar.

Bahasa antarmuka: **Indonesia**.

---

## ✨ Fitur Utama

- **13 metode analisis**: info, exif, strings, binwalk, steghide, LSB, zsteg,
  JPEG structure, carve, dd, dan lain-lain.
- **Steghide + brute-force passphrase** dengan wordlist.
- **LSB & bit-plane analysis** (termasuk visualisasi ke PNG).
- **Carve / binwalk** untuk mengekstrak file yang disisipkan.
- **`full` / `auto`**: jalankan SEMUA metode sekaligus.
- Pencarian pola flag otomatis dalam string.
- Hasil diorganisir rapi per gambar.

---

## 🚀 Cara Pakai

```bash
# 1) Menu interaktif (pilih file)
./img_steg_tool.sh

# 2) Pilih file lalu menu
./img_steg_tool.sh /path/img.png

# 3) Jalankan satu metode langsung
./img_steg_tool.sh /path/img.png steghide

# 4) Steghide dengan passphrase
./img_steg_tool.sh -p 'rahasia123' /path/img.png steghide

# 5) Brute-force passphrase dengan wordlist
./img_steg_tool.sh -w wordlist.txt /path/img.png steghide-brute

# 6) Extract manual by offset via dd
./img_steg_tool.sh -o <offset> -s <size> /path/img.png dd

# 7) Jalankan SEMUA metode
./img_steg_tool.sh /path/img.png full
```

---

## 📚 Daftar Metode

| Method | Fungsi |
|--------|--------|
| `info` | Informasi dasar file & `identify` |
| `exif` | Metadata EXIF + flag menarik |
| `strings` | Ekstraksi string + pola flag + cek trailing data |
| `binwalk` | Scan signature file tersembunyi |
| `steghide` | Extract data tersembunyi (pakai `-p` untuk passphrase) |
| `steghide-brute` | Brute-force passphrase dgn wordlist (`-w`) |
| `lsb` | Ekstrak stream LSB tiap channel + cari string |
| `lsb-msb` | Ekstrak bit 0/1/7 tiap channel |
| `bitplane` | Simpan visualisasi ke-8 bit tiap channel ke PNG |
| `zsteg` | Semua metode zsteg (PNG/BMP) |
| `jpeg` | Analisa segment/struktur JPEG + trailing |
| `carve` | Ekstrak file tersembunyi (`binwalk`) |
| `dd` | Extract manual by offset (`-o offset [-s size]`) |
| `full` / `auto` | Jalankan SEMUA metode |

> Env var `STEG_STRING_PAT` bisa di-set untuk regex pola string tambahan.

---

## 💡 Contoh Nyata (telah diuji)

Menyembunyikan lalu mengekstrak flag dengan steghide:

```bash
# Sembunyikan flag di dalam gambar BMP
steghide embed -cf gambar.bmp -ef secret_flag.txt -p rahasia123

# Ekstrak via tool
./img_steg_tool.sh -p 'rahasia123' gambar.bmp steghide
# → SUKSES! File diekstrak ke img_result/img_*/steghide.bin
#   isinya: KTCG{stego_inside}
```

Scan cepat semua metode:

```bash
./img_steg_tool.sh gambar.png full
```

✅ **Hasil pengujian**: semua metode utama `[OK]` (info, exif, strings, binwalk,
steghide, steghide extract, lsb, zsteg, carve); flag `KTCG{stego_inside}`
berhasil diekstrak.

---

## 📂 Hasil Output

```
img_result/                  # folder tempat tool dijalankan
└── img_<id>/
    ├── steghide_info.txt    # hasil steghide info
    ├── steghide.bin         # hasil extract steghide
    ├── (file carve / lsb raw / bitplane PNG)
    └── ...
```

---

## 🔧 Dependensi

| Tool | Untuk |
|------|-------|
| `steghide` | embed/extract/brute stego |
| `zsteg` | metode zsteg (PNG/BMP) |
| `exiftool` | metadata EXIF |
| `binwalk` | scan & carve file tersembunyi |
| `imagemagick` (`identify`/`convert`) | info & bitplane visual |
| `python3` + `numpy` + `Pillow` | LSB / bit-plane analysis |
| `strings` | ekstraksi string |

Semua kebutuhan bersifat **opsional per modul** — tool hanya memperingatkan
jika modul yang dipilih butuh tool yang belum terpasang.

---

## ⚠️ Catatan

- **steghide** hanya mendukung format gambar tertentu (BMP, JPEG). Untuk PNG
  gunakan metode `zsteg` / `lsb` / `binwalk`.
- Tanpa passphrase yang benar, `steghide` tidak bisa mengekstrak; gunakan
  `steghide-brute` dengan wordlist bila mencurigai passphrase lemah.
- `steghide info` akan menanyakan konfirmasi; tool otomatis menjawab `y`.
