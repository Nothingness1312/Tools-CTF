# 🔎 Strings & Regex Toolkit — Universal File Search

Tool CLI (Bash) untuk **mencari string/regex di SEMUA jenis file** — bukan
hanya `.txt` atau teks biasa. Bekerja pada file teks, binary, executable
(ELF/PE/Mach-O), **disk image** (`.img`/`.dd`/`.raw`/`.bin`), **virtual disk**
(vmdk/vdi/vhd/qcow2), **arsip** (zip/7z/gz/tar/rar), **dokumen** (pdf/docx),
gambar, **pcap**, database, dan tipe file apapun.

Menggabungkan kekuatan `strings` + `grep` + `regex` + `python3` + (`binwalk`/
`7z` opsional) untuk ekstraksi dan pencarian menyeluruh.

Bahasa antarmuka: **Indonesia**.

---

## ✨ Fitur Utama

- **⭐ SMART SEARCH (otomatis!)** — ketik pola pendek seperti `.exe`, `jpg`,
  `flag`, `OMOP`, `192.168.1.1`, atau hex `4f4d4f50`; tool **otomatis** tebak
  jenis polanya dan bangkitkan SEMUA regex yang relevan (extension + nama file
  + isi file), lalu cari sekaligus. Tanpa perlu nulis regex manual.
- **Ekstraksi strings** dari file apapun — otomatis deteksi tipe file dan
  pilih strategi terbaik (teks langsung / binary via `strings`).
- **Regex search** di semua file — single file, atau rekursif seluruh folder
  (scan teks + binary sekaligus).
- **Flag/secret hunt** — auto-deteksi pola `KTCG{...}`/`OMOP{...}`/`flag{...}`
  + kandidat ter-encode (base64/hex).
- **Disk & virtual disk search** — cari di image disk (mount + recursive,
  atau fallback strings di raw bytes).
- **Hex pattern search** — temukan offset byte di binary.
- **Nested/embedded file extraction** — bongkar file tersembunyi via binwalk.
- **Encode detection & decode** — temukan string base64/hex/URL/ROT13/JWT
  yang mengintai di dalam file.
- **Analisis** — entropi (deteksi enkripsi/compress), info file, magic bytes.
- **Flag prefix dinamis** (`--prefix`, env `FLAGPREFIX`, `.strings_tool.conf`).

---

## ⭐ SMART SEARCH (cara utama)

Kamu cukup ketik **pola pendek** — tool otomatis menentukan jenis pola dan
mencari di nama file + isi file sekaligus:

```bash
./strings_tool.sh pola <folder> ".exe"      # cari semua file .exe + isi yang menyebut .exe
./strings_tool.sh pola <folder> "jpg"       # file *.jpg + yang menyebut jpg
./strings_tool.sh pola <folder> "flag"      # file/konten berisi 'flag'
./strings_tool.sh pola <folder> "OMOP"      # cari teks OMOP (prefix flag)
./strings_tool.sh pola <folder> "192.168.1.1"  # cari alamat IP (dot di-escape otomatis)
./strings_tool.sh pola <folder> "4f4d4f50"  # cari string hex
```

### Jenis pola yang dideteksi otomatis

| Kamu ketik | Tool otomatis lakukan |
|-------------|----------------------|
| `.exe` / `.jpg` (diawali titik) | cari file berakhiran `.exe` (nama) + string `.exe` (isi) |
| `jpg` / `txt` (tanpa titik) | cari file `*.jpg` (nama) + kata `jpg` (isi) |
| `flag` / `secret` / `key` / `token` | cari nama file & konten yang memuat kata tsb |
| `OMOP` / teks bebas | cari nama file & konten yang memuat teks tsb |
| `192.168.1.1` | cari IP (titik otomatis di-escape jadi regex) |
| `http://...` / `example.com` | cari URL |
| `4f4d4f50` (hex genap ≥8) | cari byte hex (lower+upper) |

Di menu interaktif, pilih **0) Smart search pola** — paling cepat.

---

## 🚀 Cara Pakai

```bash
# 1) Menu interaktif (pilih 0 untuk SMART search)
./strings_tool.sh

# 2) Strings cepat (semua tipe file)
./strings_tool.sh <file>

# 3) Sub-perintah spesifik
./strings_tool.sh pola <folder> <pola>         # ★ SMART search (otomatis!)
./strings_tool.sh str <file> [minlen]              # extract strings
./strings_tool.sh regex <file> <pattern>           # regex search
./strings_tool.sh flag <file>                      # hunt flag/secret
./strings_tool.sh scan <folder> <pattern>          # recursive search
./strings_tool.sh hex <file> <hex-pattern>         # cari hex di binary
./strings_tool.sh nest <file>                      # extract embedded files
./strings_tool.sh multi <file> <pola1,pola2>       # multi-pattern search
./strings_tool.sh encode <file>                    # deteksi string ter-encode
./strings_tool.sh stat <file>                      # info & entropi
./strings_tool.sh deep <file> <pattern>            # deep search (4 method)
./strings_tool.sh disk <disk-image> <pattern>      # search di disk image
./strings_tool.sh files [folder]                   # list files + tipe
./strings_tool.sh batch <file>                     # batch hunt semua pola
```

---

## 📚 Sub-Perintah

```
pola      - ★ SMART search: ketik pola pendek (.exe/jpg/flag/OMOP/IP/hex),
            otomatis bangkitkan regex + cari nama & isi file sekaligus
str       - ekstraksi strings (semua tipe; otomatis pilih strategi)
regex     - regex search pada satu file (teks / binary)
flag      - hunt flag/secret + kandidat ter-encode
scan      - recursive regex search seluruh folder
hex       - cari pola hex di binary (offset + hex + ASCII)
nest      - extract file embedded (binwalk / 7z fallback)
multi     - cari banyak pola sekaligus (koma-pisah)
encode    - deteksi & decode string ter-encode (base64/hex/url/rot/jwt)
stat      - info file, entropi, jumlah string, magic bytes
deep      - deep search 4 metode: grep + strings + hex + XOR brute
disk      - search di disk/virtual disk image
files     - daftar semua file + tipe + ukuran
batch     - hun semua pola umum CTF/forensics sekaligus
```

---

## 🏳️ Flag Prefix (PENTING)

Default mencari pola `KTCG{...}`/`flag{...}`/`{}`. Untuk format flag lain:

```bash
# 1) Argumen CLI
./strings_tool.sh --prefix 'OMOP,KTCG,CTF,{}' flag <file>

# 2) Environment variable
export FLAGPREFIX='OMOP,KTCG,flag'
./strings_tool.sh flag <file>

# 3) File konfigurasi
echo 'FLAGPREFIX=OMOP,{}' > .strings_tool.conf
./strings_tool.sh flag <file>
```

---

## 💡 Contoh Nyata (telah diuji pada challenges)

```bash
# Deteksi flag ter-encode di dalam pcap
./strings_tool.sh encode traffic.pcap
# → [HEX] auth token: 4f4d4f507b653473795f706334705f30337d -> OMOP{e4sy_pc4p_03}

# Recursive scan folder untuk flag
./strings_tool.sh scan challenges "OMOP|flag"

# Cari hex file signature di binary
./strings_tool.sh hex stego.png 89504e47
# → 0x00000000  89 50 4e 47 ... .PNG...

# Extract file tersembunyi dari gambar (binwalk)
./strings_tool.sh nest gallery.png

# Deep search (4 metode sekaligus)
./strings_tool.sh deep binary "OMOP|KTCG"
```

✅ **Hasil pengujian**: deteksi tipe file otomatis bekerja pada `.txt`, binary,
`.dat`, `.jpg`, `.png`, `.pcap`, disk image; flag terdeteksi di berbagai tipe.

---

## 📂 Hasil Output

```
strings_result/                  # folder tempat tool dijalankan
└── <nama_file>_nested/          # hasil ekstraksi nest (binwalk)
```

---

## 🔧 Dependensi

| Tool | Kebutuhan |
|------|-----------|
| `file` | deteksi tipe file (wajib) |
| `strings` | ekstraksi string (binutils) |
| `grep` | regex search (wajib) |
| `xxd` | hexdump magic bytes (wajib) |
| `python3` | encode detect, hex search, entropi (wajib) |
| `binwalk` | opsional, ekstraksi file embedded |
| `7z` | opsional, fallback extract arsip/disk |

Install: `sudo apt install file binutils xxd python3 binwalk p7zip-full`.

---

## ⚠️ Catatan

- Untuk file terkait **disk/unmount info** (mount read-only, auto-unmount),
  lihat tool terpisah: `forensics_tool.sh`.
- `nest` akan **mengeksekusi binwalk** pada file target — biarkan berjalan
  bila target legitimate; jangan jalankan pada file yang mencurigakan di
  sistem produksi tanpa sandbox.
- Entropi mendekati 8 → data terenkripsi/terkompresi.
- `hex` mencari pola **byte mentah** di binary; untuk ASCII yang ditulis
  sebagai teks hex, gunakan `encode`/`deep` sebagai gantinya.
