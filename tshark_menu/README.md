# 🌐 TShark Menu — Network Capture Forensics Toolkit (Packet Analysis)

Tool CLI (Bash) yang membungkus `tshark` (CLI Wireshark) menjadi menu
terstruktur untuk analisis capture jaringan (*packet capture / pcap*).
Ditujukan untuk investigasi forensik network di challenge CTF.

Bahasa antarmuka: **Indonesia**.

---

## ✨ Fitur Utama

- **13 menu analisis**: ringkasan, protocol tree, proses paket, HTTP, DNS,
  credentials, follow stream, export objects, dan lain-lain.
- **Export Objects HTTP**: mengekstrak file yang di-transfer via HTTP (biasanya
  berisi flag).
- **Follow TCP stream**: melihat isi percakapan (misalnya isi HTTP request/response).
- **Filter Wireshark**: terapkan display filter custom.
- **Hexdump & detail paket**: inspeksi byte per paket.
- **Mode langsung**: jalankan menu tertentu tanpa interaktif.
- Hasil diorganisir rapi per sesi.

---

## 🚀 Cara Pakai

```bash
# 1) Menu interaktif
./tshark_menu.sh

# 2) Dengan file capture
./tshark_menu.sh /path/capture.pcap

# 3) Dengan direktori (akan scan pcap di dalamnya)
./tshark_menu.sh /path/captures_dir
```

Tanpa argumen, tool mencari file `.pcap`/`.pcapng` di direktori aktif &
subdirektori secara otomatis.

---

## 🖥️ Menu Utama

```
 1) Ringkasan capture           2) Protocol Hierarchy
 3) Paket (list ringkas)        4) Proses paket (statistik)
 5) HTTP request                6) DNS query
 7) Credentials                 8) Follow TCP stream
 9) Export objects (HTTP)      10) List paket (n baris)
11) Filter display custom      12) Hexdump paket
13) Detail paket (full)
   L) Toggle save log    Q) Keluar
```

---

## 💡 Contoh Nyata (telah diuji)

Capturing lalu analisis HTTP yang mengandung flag:

```bash
# 1) Buat capture HTTP sederhana
python3 -m http.server 8766 &
dumpcap -q -i lo -w cap.pcapng &
curl http://127.0.0.1:8766/index.txt

# 2) Analisis: ringkasan + protocol + HTTP request
./tshark_menu.sh cap.pcapng

# 3) Export objects HTTP → flag diekstrak dari index.txt
./tshark_menu.sh cap.pcapng   # pilih menu 9
```

✅ **Hasil pengujian**: semua menu utama `[OK]`; export objects berhasil
mengekstrak `index.txt` berisi `KTCG{http_flag}` ke folder
`tshark_result/export_<id>/`.

---

## 📂 Hasil Output

```
tshark_result/                 # folder tempat tool dijalankan
├── export_<id>/               # hasil export objects (file yang ditransfer)
│   └── index.txt
└── tshark_session_<ts>.log    # jika log diaktifkan
```

---

## 🔧 Dependensi

| Tool | Kebutuhan |
|------|-----------|
| `tshark` | wajib (paket `tshark`) |
| `dumpcap` | opsional, untuk menangkap |
| `text2pcap` / `mergecap` | opsional |

---

## ⚠️ Catatan

- Membutuhkan akses `tshark` dan kemampuan baca file pcap.
- Export objects hanya dapat mengekstrak objek yang benar-benar tertransfer
  (mis. file yang di-`GET`), bukan semua paket.
- Untuk capture langsung butuh hak akses interface (bisa pakai `sudo dumpcap`).
