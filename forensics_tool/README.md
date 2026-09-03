# 💾 Forensics Tool — Disk Image / Archive Forensics Toolkit

Tool CLI (Bash) untuk analisis **disk image** (`.img`, `.raw`, `E01`, `vmdk`,
`vdi`, `vhd`, `qcow2`, `iso`) dan **archive** (`.zip`, `.tar`, `.7z`, ...)
dalam forensik & CTF. Mendeteksi tipe image, melakukan mount/extract otomatis,
menyalin file, dan carving file tersembunyi.

Bahasa antarmuka: **Indonesia**.

---

## ✨ Fitur Utama

- **Deteksi otomatis tipe image** (raw disk, E01, vmdk/vdi/vhd/qcow2, iso, archive).
- **Mount & auto-extract** lalu **auto-unmount** — menangani image disk mentah.
- **Copy file** dari image yang berhasil di-mount.
- **Carving** (binwalk) untuk menemukan file yang dihapus/tersembunyi.
- Cek integritas partition & filesystem.
- Mendukung banyak format via `7z`/`binwalk` sebagai fallback.
- Hasil disalin ke folder output yang rapi.

---

## 🚀 Cara Pakai

```bash
# 1) Menu interaktif
./forensics_tool.sh

# 2) Analisis + extract otomatis
./forensics_tool.sh <file-image>

# 3) Perintah spesifik
./forensics_tool.sh info <file>
./forensics_tool.sh detect <file>
./forensics_tool.sh mount <file>      # mount ke /mnt/<nama>
./forensics_tool.sh extract <file>    # mount/extract + salin file
./forensics_tool.sh carve <file>
./forensics_tool.sh unmount           # unmount semua + lepas loop
```

---

## 📚 Perintah & Fungsi

| Perintah | Fungsi |
|----------|--------|
| `info` | Informasi detail image / file |
| `detect` | Deteksi tipe image (raw-disk, E01, vmdk/vdi/vhd/qcow2, iso, archive) |
| `mount` | Mount image ke `/mnt/<nama>` (pakai loop device / 7z) |
| `extract` | Extract/mount + salin isi ke folder hasil |
| `carve` | Carving file tersembunyi (binwalk) |
| `unmount` | Unmount semua mount + lepas semua loop device |

---

## 💡 Contoh Nyata (telah diuji)

```bash
# Image zip berisi flag
./forensics_tool.sh extract sample_disk.zip
# → 7z extract berhasil → isi flag.txt = KTCG{disk_flag}

# Raw disk image (mbr)
./forensics_tool.sh detect rawdisk.img
# → Detected: raw-disk  (tipe benar)

# Menemukan file yang tersembunyi
./forensics_tool.sh carve sample_disk.zip
```

✅ **Hasil pengujian**: `detect` (zip→archive, raw→raw-disk), `extract`,
`carve`, `usage`, dan `unmount` semuanya `[OK]`; flag `KTCG{disk_flag}`
berhasil diekstrak.

---

## 📂 Hasil Output

```
forensics_result/            # folder tempat tool dijalankan
├── (isi file hasil extract / copy)
└── ...
```

Mount sementara menggunakan `/mnt/` dan otomatis dilepas kembali setelah selesai.

---

## 🔧 Dependensi

| Tool | Untuk |
|------|-------|
| `7z` / `7za` | extract archive |
| `binwalk` | carving / signature scan |
| `fdisk` / `partx` | deteksi & mount partition |
| `losetup` | loop device (raw disk mount) |
| `mount` / `umount` | mount filesystem (butuh **root**) |

> Debian/Ubuntu: `sudo apt install p7zip-full binwalk fdisk mount`.

---

## ⚠️ Catatan

- **Mount image disk** memerlukan **hak root (`sudo`)** untuk membuat loop
  device dan mount sebenarnya. Tanpa root, tool akan memberi peringatan dan
  hanya melakukan extract (zip/7z) atau analisis statis.
- Tool opsional memakai `ewfmount`, `qemu-nbd`, `fuse2fs`, `guestmount`,
  `genisoimage` bila tersedia — namun tetap berfungsi dengan fallback
  `7z`/`binwalk` jika tidak ada.
- Deteksi tipe menggunakan **magic bytes**; pastikan file tidak ternama
  menyesatkan (mis. zip yang dinamai `.img` tetap terdeteksi sebagai archive).
- Command `unmount` selalu aman: hanya melepas mount/loop yang dibuat tool.
