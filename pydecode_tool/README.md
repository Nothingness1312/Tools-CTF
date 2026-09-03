# 🐍 PyDecode Tool — Template Decoder All-in-One (Python)

**Kerangka / template Python kosongan** untuk decode & dekripsi segala macam
format di CTF / forensik, yang **tinggal kamu ubah-ubah isinya** sesuai
kebutuhan. Bukan tool jadi — ini **skeleton** dengan semua modul utama sudah
disusun, tinggal diisi.

Nama package yang dianjurkan (bisa kamu ganti): `pydecode_tool/`

---

## 📁 Isi Folder

```
pydecode_tool/
├── template_decoder.py   # TEMPLATE UTAMA (skeleton all-in-one)
└── README.md             # ini
```

---

## 🧬 Struktur Template (di dalam `template_decoder.py`)

Setiap class = satu "kategori". Cukup pakai bagian yang kamu butuhkan.

| Class | Isi | Buat apa |
|-------|-----|----------|
| `Util` | fungsi bantu (baca file, cek hex, ROT, is_printable) | dipakai semua modul |
| `Encoding` | base64/32/58/91, hex, url, html, rot13/47, caesar, bin, uu, quopri | decode encoding macam-macam |
| `Symmetric` | AES-128/192/256, DES, 3DES, RC4 (mode cbc/ecb/ctr/cfb/ofb) + padding | dekripsi cipher simetris |
| `SaltKdf` | format `Salted__`, EVP_BytesToKey, PBKDF2 | pecah salt & turunkan key/IV dari password |
| `SSL` | load kunci RSA, RSA decrypt/encrypt, parse sertifikat, PEM↔DER | urus SSL/sertifikat/pem |
| `AutoExtract` | regex cari `key=`, `iv=`, `salt=`, `mode=`, `iter=` di konteks | auto-key/IV/salt |
| `Xor` | XOR biasa + brute single-byte + multi-byte | pecah XOR |
| `AutoDecoder` | orchestrator: auto_detect, try_everything, salted_file, crack_with_auto_params | satu pintu masuk |

---

## 🚀 Cara Pakai Template

### 1) Jalankan demo cepat
```bash
python3 template_decoder.py --demo
```

### 2) Kerja normal: ubah isi fungsi yang kamu butuhkan

Semua bagian yang **harus kamu isi / sesuaikan** ditandai jelas dengan:

```python
### >>> ISI DI SINI:  ...
pass  # TODO
```

Contoh: mau pakai **base64** — tidak perlu ubah apa-apa, langsung:

```python
from template_decoder import AutoDecoder
d = AutoDecoder()
d.load_string("S0lUQ0d7ZmxhZ30=")
print(d.enc.base64(d._input))       # -> b'KITCG{flag}'
```

Contoh: mau **AES-256-CBC dari file openssl salted**:

```python
from template_decoder import AutoDecoder
d = AutoDecoder()
pt = d.salted_file("secret.enc", "password", kdf="evp")
print(pt)
```

Contoh: biarkan tool **cari sendiri key/iv/salt** lalu decrypt:

```python
from template_decoder import AutoDecoder
d = AutoDecoder()
pt = d.crack_with_auto_params("blob.bin", password="hint")
print(pt)
```

### 3) Cara integrasi: import langsung dari script lain

```python
# script_ku.py
from template_decoder import AutoDecoder, Symmetric, SaltKdf, AutoExtract
```

---

## 📝 Cara Mengisi Tiap Section (Panduan Lengkap)

### A. `Encoding` — tambah/ubah format
Cukup tambah method baru di dalam class `Encoding`. Setiap method harus:
- terima `data: bytes` → kembalikan `bytes`.
- lempar `Exception` bila input tidak cocok (dibiarkan kecuali oleh caller).

```python
def base58(self, data: bytes) -> bytes:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    ### >>> ISI DI SINI: implementasi decode base58
    pass
```

### B. `Symmetric` — set key/IV/mode
Inisialisasi dengan key & IV, lalu panggil method:

```python
from template_decoder import Symmetric
s = Symmetric(key=b"0123456789abcdef", iv=b"abcdefghijklmnop", mode="cbc")
pt = s.aes(ciphertext, keysize=16)
```

Kalau key/IV belum tahu, biarkan kosong dan pakai `AutoExtract`.

### C. `SaltKdf` — pecah salt & KDF
- `split_openssl_salt(data)` → pisahkan salt dari ciphertext.
- `evp_bytes_to_key(pass, salt, ...)` → KDF openssl klasik (md5).
- `pbkdf2(pass, salt, ...)` → KDF modern.
- `decrypt_salted_file(path, pass, kdf=...)` → buka file salted langsung.

### D. `SSL` — sertifikat & RSA
- RSA decrypt: `ssl.rsa_decrypt(enc, "priv.pem", oaep=True)`
- Load kunci: `ssl.load_private_key("priv.pem")`
- `cert_info(path)` → parsing X.509 (isi sendiri di `### >>> ISI DI SINI`).

### E. `AutoExtract` — otak auto key/IV/salt
Fungsi `find(blob)` memindai bytes apapun untuk pola:
```
key=, iv=, salt=, mode=, iter=
```
Kamu bisa menambah pola sendiri (mis. `password=`, `nonce=`, `tag=`).

### F. `Xor`
```python
from template_decoder import Xor
Xor.xor(data, b"rahasia")
Xor.brute_single_byte(data)      # coba semua key 1 byte
Xor.brute_multi_byte(data, 4)    # key pendek (isi sendiri)
```

---

## 🧰 Dependensi (opsional)

| Package | Untuk | Install |
|---------|-------|---------|
| `pycryptodome` | AES/DES/3DES/RC4/RSA (wajib utk cipher & RSA) | `pip install pycryptodome` |
| `cryptography` | cipher alternatif + parse sertifikat | `pip install cryptography` |

> Template tetap bisa **import & jalankan** walau kedua package belum ada —
> hanya cipher/RSA yang butuh package akan menandakan fallback ke `openssl`
> CLI (isi sendiri di `### >>> ISI DI SINI`).

---

## 🔧 Tips Pemakaian

- **Jangan jalankan semua sekaligus** — panggil method spesifik yang kamu
  butuhkan; `try_everything()` cuma untuk cek cepat.
- **Auto-detect bisa kena false-positive** (mis. base64 berisi teks read). Cek
  hasil yang paling "manusiawi".
- Kalau cipher butuh parameter tak biasa (GCM, nonce, AAD), tambahkan field
  di class `Symmetric` dan method baru — pola sudah mirip.
- Semua method memakai `bytes`; untuk menampilkan gunakan
  `.decode('utf-8', 'ignore')`.

---

## ✅ Status

- Template **sudah teruji**: `python3 -m py_compile` valid, `--demo` jalan &
  berhasil auto-detect base64.
- Skeleton lengkap siap diisi — silakan tambah/ubah method sesuai kebutuhanmu.
