# 🔓 Decode Tool — Toolkit Dekripsi & Decode (CTF)

Tool CLI (Bash) untuk mendekode / mendekripsi berbagai format teks, file, dan
cipher umum yang sering muncul di challenge CTF. Cocok dipakai saat kamu
menemukan ciphertext atau file terenkripsi dan tidak tahu formatnya.

Dibuat dan ditulis dalam bahasa **Indonesia**.

---

## ✨ Fitur Utama

- **Auto-detect**: cukup beri string, tool menebak encoding/cipher-nya otomatis.
- **23+ metode decode**: base64, hex, rot13/rot47, caesar, vigenere, XOR,
  URL/HTML escape, binary, JWT, Fernet, dan lain-lain.
- **Dukungan kunci & file**: input bisa string atau file; output bisa ke file.
- **AES / DES / RC4 / SM4**: dekripsi simetris via OpenSSL dengan berbagai mode.
- **hashid**: mendeteksi jenis hash.
- **XOR bruteforce**: coba semua key 1-byte otomatis.
- Clean & berwarna, hasil disimpan rapi.

---

## 🚀 Cara Pakai

```bash
# 1) Menu interaktif
./decode_tool.sh

# 2) Auto-detect satu string
./decode_tool.sh "ciphertext..."

# 3) Decode langsung dengan metode tertentu
./decode_tool.sh base64 "c2VjcmV0Cg=="
./decode_tool.sh rot13 "frperg"

# 4) Dengan kunci
./decode_tool.sh -k "keyrahasia" vigenere "..."

# 5) Input dari file
./decode_tool.sh -k "key" -f file.enc aes-256-cbc

# 6) Output ke file
./decode_tool.sh -k "key" -f file.enc -o keluar.txt aes-256-cbc
```

---

## 📚 Daftar Metode

| Format/Cipher | Method |
|---------------|--------|
| Base64 / 32 / 58 | `base64` `base32` `base58` |
| Hex & Binary | `hex` `bin` |
| URL & HTML | `url` `html` |
| ROT | `rot13` `rot47` |
| Substitusi | `caesar` `vigenere` |
| XOR | `xor` `xorhex` `xor-bruteforce` |
| Escape | `escape` |
| OpenSSL AES | `aes-128-ecb` `aes-192-cbc` `aes-256-cbc` `aes-256-ctr` `aes-256-cfb` `aes-256-ofb` |
| OpenSSL Lain | `des-cbc` `des-ede3-cbc` `rc4` `sm4-cbc` |
| Token | `jwt` `fernet` |
| Lainnya | `hashid` `auto` |

> **Key hex**: untuk cipher yang butuh key/IV biner, set `export KEYHEX=<hex>`
> dan `export IVHEX=<hex>`.

---

## 💡 Contoh Nyata (telah diuji)

```bash
# Decode base64
./decode_tool.sh base64 "S1RDR3tmbGFnfQ=="          # → KTCG{flag}

# Caesar dengan geseran 3
./decode_tool.sh -k 3 caesar "nhvhuw"

# Vigenere
./decode_tool.sh -k "key" vigenere "..."

# XOR satu byte
./decode_tool.sh xor "ciphertext"

# AES-256-CBC dari file terenkripsi
./decode_tool.sh -k "supersecret" -f secret.enc aes-256-cbc

# Auto-detect (tebak otomatis)
./decode_tool.sh "Q2V5ZW5uZQ=="
```

✅ **Hasil pengujian**: semua 18 metode utama berhasil (`[OK]`); flag
`KTCG{...}` berhasil didecode dari file AES (`dec_*`).

---

## 📂 Hasil Output

```
decode_result/
└── dec_<timestamp>_<method>/
    ├── <method>.txt        # hasil decode teks
    └── (file)              # hasil decode biner
```

Folder output dibuat di **folder tempat tool dijalankan** (`$(pwd)/decode_result`).

---

## 🔧 Dependensi

| Tool | Kebutuhan |
|------|-----------|
| `base64`, `base32` | coreutils (bawaan) |
| `xxd`, `od` | vim-common (hex/binary) |
| `openssl` | AES/DES/RC4/SM4 |
| `python3` | JWT, Fernet, caesar, vigenere |

Cek otomatis dilakukan tool; jika ada yang kurang, tool akan memberi peringatan
untuk metode yang membutuhkannya.

---

## ⚠️ Catatan

- Untuk output biner (AES/hash) gunakan `-o` agar tidak merusak terminal.
- `hashid` hanya **mendeteksi** jenis hash, bukan mendekripsi.
- Tanpa metode, tool mencoba auto-detect: untuk cipher ber-kunci selalu
  berikan key dengan `-k` agar hasil akurat.
