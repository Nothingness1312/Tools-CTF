# 🔬 RE Tool — Reverse Engineering & Flag Finder (ELF/Binary)

Tool CLI (Bash) untuk **reverse engineering** file biner (ELF) dan pencarian
flag secara cepat. Menggabungkan `file`, `strings`, `objdump`/`gdb`/`radare2`,
analisis crypto, entropy, dan auto-decode untuk menemukan flag di challenge
reversing.

Bahasa antarmuka: **Indonesia**.

---

## ✨ Fitur Utama

- **Analisis cepat**: satu perintah → info + flag.
- **16 sub-perintah** lengkap untuk RE.
- **Flag prefix dinamis** (`--prefix`, env `FLAGPREFIX`, atau `.re_tool.conf`).
- **Highlight flag** (`[F]` berwarna) pada hasil strings.
- **Auto-decode chain** (base64 → hex → ...) pada pencarian flag.
- **Disassembly** per fungsi, **dekompilasi** string/data, **crypto** & **entropy**
  detection, **XOR** brute, **keys** extraction.
- **Jalankan binary** langsung dari tool.
- Hasil rapi per sesi.

---

## 🚀 Cara Pakai

```bash
# 1) Menu interaktif
./re_tool.sh

# 2) Analisis cepat (info + flag)
./re_tool.sh <file>

# 3) Sub-perintah spesifik
./re_tool.sh info <file>
./re_tool.sh strings <file> [pola]
./re_tool.sh section <file> [nama]
./re_tool.sh disasm <file> [fungsi]
./re_tool.sh data <file> [section]
./re_tool.sh crypto <file>
./re_tool.sh xor <file> [hex-ciphertext]
./re_tool.sh keys <file>
./re_tool.sh entropy <file>
./re_tool.sh run <file> [args...]
./re_tool.sh flag <file>
```

---

## 📚 Sub-Perintah

```
info      - info file, arsitektur, sections, protections
strings   - ekstraksi string (+ pencarian pola / flag)
section   - detail section (headers, flags)
disasm    - disassembly fungsi (default: main)
data      - tampilkan data/string pada section
funcs     - daftar fungsi
main      - lokasi & disasm main
refs      - referensi / cross-reference penting
crypto    - deteksi konstanta/cipher crypto (S-box, dll)
xor       - XOR brute / decode
keys      - ekstraksi key / hardcoded strings
entropy   - hitung entropy per section (deteksi enkripsi/compress)
hidden    - cari string / data tersembunyi
run       - jalankan binary dengan argumen
strace    - trace system call (jika tersedia)
radare     - analisis via radare2 (jika tersedia)
flag      - pencarian flag + auto-decode
```

---

## 🏳️ Flag Prefix (PENTING)

Secara default tool mencari pola `KTCG{...}`. Untuk challenge yang memakai
format flag lain, set prefix lewat **tiga cara**:

```bash
# 1) Argumen CLI
./re_tool.sh --prefix 'KTCG,CTF,{}' flag <file>

# 2) Environment variable
export FLAGPREFIX='KTCG,MyCTF,flag'
./re_tool.sh <file>

# 3) File konfigurasi
echo 'FLAGPREFIX=KTCG,{}' > .re_tool.conf
./re_tool.sh flag <file>
```

---

## 💡 Contoh Nyata (telah diuji)

```bash
# Binary sederhana mengandung flag KTCG{...}
./re_tool.sh salam_kenal
# → flag ditemukan: KTCG{s4lam_k3n4l_dun1a_ctf}

# Cari flag dengan prefix custom
./re_tool.sh --prefix 'KTCG,CTF,{}' flag salam_kenal

# Disassembly fungsi main
./re_tool.sh disasm binary main

# Deteksi konstanta crypto
./re_tool.sh crypto binary

# Hitung entropy (temukan bagian terenkripsi)
./re_tool.sh entropy binary

# Jalankan binary
./re_tool.sh run binary arg1 arg2
```

✅ **Hasil pengujian**: semua 16 sub-perintah `[OK]`; flag `KTCG{...}`
terdeteksi baik dengan prefix default maupun `--prefix 'KTCG,CTF'`.

---

## 📂 Hasil Output

```
re_result/                   # folder tempat tool dijalankan
└── (hasil analisis / log per sesi)
```

---

## 🔧 Dependensi

| Tool | Kebutuhan |
|------|-----------|
| `file` | deteksi tipe file (wajib) |
| `strings` | ekstraksi string (binutils) |
| `objdump` | disasm / section (binutils) |
| `gdb` | opsi tambahan (disasm/debug) |
| `radare2` (`r2`) | opsional, analisis lanjutan |
| `readelf` | section headers (binutils) |
| `strace` | opsional, system call trace |

Install: `sudo apt install binutils file gdb radare2 strace`.

---

## ⚠️ Catatan

- Disassembly berfungsi baik untuk ELF yang **tidak di-strip**; pada binary
  stripped, symbol `main` mungkin berubah nama — gunakan `funcs`/`disasm`
  dengan alamat atau urutan.
- `run` akan **mengeksekusi** binary; berhati-hati dengan binary yang
  mencurigakan / berbahaya (jalankan di sandbox bila perlu).
- `entropy` mengindikasikan data terenkripsi/terkompresi (nilai mendekati 8).
- Untuk binary dengan sumber kompilasi, cari bagian pembanding flag yang
  biasanya literal (`strings`) atau hasil transformasi (XOR/base64).
