# 🧠 Volatility 3 Menu — Memory Forensics Toolkit

Tool CLI (Bash) yang membungkus **Volatility 3** menjadi menu terstruktur untuk
analisis *memory dump* (image RAM) dalam investigasi forensik & CTF. Berguna
untuk menemukan proses mencurigakan, koneksi jaringan, file yang dihapus,
malware, password hash, dan flag dalam memori.

Bahasa antarmuka: **Indonesia**.

---

## ✨ Fitur Utama

- **Deteksi OS otomatis** dari image (Windows / Linux / macOS).
- **20 menu plugin Volatility 3** yang paling sering dipakai.
- **Pencarian file image** di direktori aktif secara otomatis.
- **Dump proses & dump file** untuk analisis lebih lanjut.
- **Pencarian string** di seluruh memori atau di dump proses tertentu.
- **Plugin manual** untuk menjalankan plugin Volatility bebas.
- **Mode langsung**: jalankan plugin tertentu tanpa interaktif.
- Hasil disimpan rapi + opsi log sesi.

---

## 🚀 Cara Pakai

```bash
# 1) Menu interaktif (scan image di direktori)
./vol_tool.sh

# 2) Dengan image memory
./vol_tool.sh /path/image.mem

# 3) Jalankan plugin langsung (non-interaktif)
./vol_tool.sh /path/image.mem pslist
./vol_tool.sh /path/image.mem windows.netscan.NetScan
```

---

## 🖥️ Menu Utama

```
 1) Info OS & image           2) Proses (list) / pstree
 4) Command line tiap proses  5) Jaringan (netscan)
 6) Jaringan (netstat)        7) File scan
 8) Dump proses memori        9) Dump file (dumpfiles)
10) Registry / hashdump      11) Cari string memori
12) Cari string dump proses  13) Malware scan (malfind)
14) Driver scan              15) Handles / DLL / VAD
16) Env vars proses          17) Timeliner
18) Bash history (linux/mac) 19) Plugin lain (manual)
20) Ganti image / OS
   L) Toggle save log   Q) Keluar
```

---

## 💡 Contoh Nyata

```bash
# Info OS + arsitektur
./vol_tool.sh dump.vmem windows.info.Info

# Daftar proses yang pernah berjalan (temukan process mencurigakan)
./vol_tool.sh dump.vmem windows.pslist.PsList

# Cari koneksi jaringan (exfil / C2)
./vol_tool.sh dump.vmem windows.netscan.NetScan

# Scan file (temukan file yang dihapus / berisi flag)
./vol_tool.sh dump.vmem windows.filescan.FileScan

# String di seluruh memori → cari flag
./vol_tool.sh dump.vmem   # pilih menu 11

# Hashdump Windows
./vol_tool.sh dump.vmem   # pilih menu 10
```

---

## 📂 Hasil Output

```
vol_result/                  # folder tempat tool dijalankan
└── vol_<pid>/
    ├── (hasil plugin, mis. dump file/proses)
    └── session_<ts>.log     # log sesi (jika diaktifkan)
```

---

## 🔧 Dependensi

| Tool | Kebutuhan |
|------|-----------|
| `vol` | **Volatility 3** (wajib, `pip install volatility3`) |
| `strings` | binutils (pencarian string) |

> **Catatan penting**: ukuran image memori bisa besar; pastikan cukup RAM/disk.

---

## ⚠️ Catatan

- **Plugin Windows** hanya berfungsi pada image Windows; tool otomatis
  menyesuaikan plugin per OS hasil deteksi.
- Membutuhkan **symbol table** yang sesuai. Jika plugin gagal dengan pesan
  "Unable to validate plugin requirements", image tersebut tidak memiliki
  symbol yang dikenali (mis. bukan image memori Volatility yang valid).
- Untuk pengujian menyeluruh/eksploitasi butuh **memory dump asli** (mis.
  dibuat dengan `dumpit`, `winpmem`, atau `/proc/kcore` dengan hak root).
  Tanpa image valid, tool dengan aman mendeteksi OS sebagai `unknown` dan
  meneruskan error dari Volatility.
- Perintah plugin memerlukan akses baca penuh terhadap file image.
