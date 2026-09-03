#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 TEMPLATE DECODER ALL-IN-ONE (PYTHON) — kerangka kosong siap diubah-ubah
================================================================================
 Template Python untuk keperluan decode/dekripsi di CTF / forensik.

 Ini BUKAN tool jadi — ini KERANGKA (skeleton). Semua modul utama sudah
 disusun; tinggal kamu buka setiap fungsi dan isi/ubah logikanya sesuai
 kebutuhan (cari tanda:  ### >>> ISI DI SINI  /  pass  # TODO ).

 Cara cepat ambil hanya yang kamu butuh:
   - Dekripsi AES/DES/RC4  -> section "CIPHER SIMETRIS"
   - Pecah salt / kdf      -> section "SALT & KDF"
   - Urus sertifikat/SSL   -> section "SSL / SERTIFIKAT / PEM"
   - Auto key/IV/salt      -> section "AUTO-EXTRACT KEY/IV/SALT"
   - Macam-macam encoding  -> section "ENCODING MACAM-MACAM"

 Jalankan contoh demo cepat:
   python3 template_decoder.py --demo
================================================================================
"""

import base64
import binascii
import hashlib
import itertools
import json
import os
import re
import string
import sys
from pathlib import Path

# --- modul opsional (instal kalau mau; kalau tidak ada tool tetap jalan) ------
try:
    from Crypto.Cipher import AES, DES, DES3, ARC4, PKCS1_OAEP
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
    HAS_PYCrypto = True
except Exception:
    HAS_PYCrypto = False

try:
    from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms, modes
    HAS_Cryptography = True
except Exception:
    HAS_Cryptography = False

# ==============================================================================
# 1. UTILITAS DASAR (bisa langsung dipakai, tinggal ubah kalau perlu)
# ==============================================================================
class Util:
    """Fungsi bantu kecil: baca file, cek hex, rotasi, dll."""

    @staticmethod
    def read(path):
        """Baca file sebagai bytes (binary-safe)."""
        return Path(path).read_bytes()

    @staticmethod
    def is_hex(s):
        """Apakah string berupa hex valid?"""
        try:
            bytes.fromhex(s.replace(" ", "").replace("0x", ""))
            return True
        except Exception:
            return False

    @staticmethod
    def hex_to_bytes(s):
        return bytes.fromhex(s.replace(" ", "").replace("0x", ""))

    @staticmethod
    def rot(data, n):
        """ROT-n pada ASCII A-Z (case-insensitive)."""
        out = []
        for ch in data:
            if "A" <= ch <= "Z":
                out.append(chr((ord(ch) - 65 + n) % 26 + 65))
            elif "a" <= ch <= "z":
                out.append(chr((ord(ch) - 97 + n) % 26 + 97))
            else:
                out.append(ch)
        return "".join(out)

    @staticmethod
    def is_printable(b, ratio=0.9):
        """Apakah mayoritas bytes printable (kemungkinan plaintext)."""
        if not b:
            return False
        good = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
        return good / len(b) >= ratio


# ==============================================================================
# 2. ENCODING MACAM-MACAM
#    (semua fungsi menerima bytes -> return bytes. Ubah isi sesuai kebutuhan)
# ==============================================================================
class Encoding:
    """Kumpulan decoder untuk format-format umum."""

    # ---------------- base family ----------------
    def base64(self, data: bytes) -> bytes:
        """Decode base64 (standar)."""
        return base64.b64decode(data)

    def base32(self, data: bytes) -> bytes:
        return base64.b32decode(data)

    def base58(self, data: bytes) -> bytes:
        """Base58 (bitcoin). PENTING: bukan builtin, perlu implementasi sendiri."""
        # Tentukan alfabet sesuai kebutuhan (bitcoin vs flickr)
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        ### >>> ISI DI SINI: implementasi decode base58
        pass  # TODO

    def base91(self, data: bytes) -> bytes:
        """Base91. Butuh implementasi sendiri."""
        ### >>> ISI DI SINI: implementasi decode base91
        pass  # TODO

    # ---------------- hex / byte ----------------
    def hex(self, data: bytes) -> bytes:
        """Decode hex -> bytes."""
        return Util.hex_to_bytes(data.decode("ascii"))

    def hex_from_file(self, path: str) -> bytes:
        """Hex dari file (stream) -> bytes."""
        txt = Util.read(path).decode("ascii").replace("\n", "").replace(" ", "")
        return Util.hex_to_bytes(txt)

    # ---------------- web ----------------
    def url(self, data: bytes) -> bytes:
        """URL percent-decoding (pakai urllib)."""
        from urllib.parse import unquote_to_bytes
        return unquote_to_bytes(data.decode("ascii"))

    def html(self, data: bytes) -> bytes:
        """HTML entity decode (&amp; &lt; &#65; ...)."""
        import html as _html
        return _html.unescape(data.decode("utf-8", "ignore")).encode()

    # ---------------- string transform ----------------
    def rot13(self, data: bytes) -> bytes:
        return Util.rot(data.decode("ascii"), 13).encode()

    def rot47(self, data: bytes) -> bytes:
        """ROT47 (semua printable ASCII 33-126)."""
        return "".join(
            chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c
            for c in data.decode("ascii")
        ).encode()

    def caesar(self, data: bytes, shift: int = 3) -> bytes:
        """Caesar shift. Ubah `shift` atau buat loop semua shift di caller."""
        ### >>> ISI DI SINI
        return Util.rot(data.decode("ascii"), shift).encode()

    # ---------------- binary ----------------
    def bin_ascii(self, data: bytes) -> bytes:
        """Decimal/binary/octal string -> bytes."""
        txt = data.decode("ascii").strip()
        base = 10
        vals = re.findall(r"\d+", txt)
        ### >>> ISI DI SINI: pilih base (2/8/10/16) lalu int(v, base) -> chr
        return bytes(int(v, base) for v in vals)

    def bin_utf8_bits(self, data: bytes) -> bytes:
        """Teks '01000001 01000010' -> bytes."""
        txt = data.decode("ascii").replace(" ", "")
        return bytes(int(txt[i : i + 8], 2) for i in range(0, len(txt), 8))

    # ---------------- misc ----------------
    def unicode_escape(self, data: bytes) -> bytes:
        """\\uXXXX / \\xXX escape -> bytes."""
        return data.decode("unicode_escape").encode("latin1", "ignore")

    def quopri(self, data: bytes) -> bytes:
        """Quoted-printable (email)."""
        import quopri
        return quopri.decodestring(data)

    def uu(self, data: bytes) -> bytes:
        """uuencode."""
        import binascii as _b
        return _b.a2b_uu(data)


# ==============================================================================
# 3. CIPHER SIMETRIS (AES / DES / RC4 / ...)
# ==============================================================================
class Symmetric:
    """Decryptor simetris. Mode CBC/CTR/CFB/OFB + padding.

    Key/IV harus diisi: dari argumen, env, atau auto-extract (lihat section 6).
    """

    def __init__(self, key=b"", iv=b"", mode="cbc", pad="pkcs7"):
        self.key = key      # bytes  (16/24/32 utk AES; 8 utk DES; 16/24 utk 3DES)
        self.iv = iv        # bytes  (size = block size)
        self.mode = mode    # cbc | ecb | ctr | cfb | ofb
        self.pad = pad      # pkcs7 | none

    # ---------------- AES ----------------
    def aes(self, ciphertext: bytes, keysize=16) -> bytes:
        """AES decrypt. keysize: 16(AES-128) | 24(192) | 32(256)."""
        if not HAS_Crypto:
            ### >>> ISI DI SINI: jalankan via openssl CLI (subprocess) sbg fallback
            return b""
        from Crypto.Cipher import AES as _AES
        if self.mode == "ecb":
            c = _AES.new(self.key, _AES.MODE_ECB)
        elif self.mode == "ctr":
            c = _AES.new(self.key, _AES.MODE_CTR, nonce=b"", initial_value=self.iv)
        else:
            c = _AES.new(self.key, _AES.MODE_CBC, self.iv)
        pt = c.decrypt(ciphertext)
        return self._unpad(pt)

    # ---------------- DES ----------------
    def des(self, ciphertext: bytes) -> bytes:
        if not HAS_PYCrypto:
            return b""
        from Crypto.Cipher import DES as _DES
        c = _DES.new(self.key[:8], _DES.MODE_CBC, self.iv[:8])
        return self._unpad(c.decrypt(ciphertext))

    def des3(self, ciphertext: bytes) -> bytes:
        if not HAS_PYCrypto:
            return b""
        from Crypto.Cipher import DES3 as _D3
        c = _D3.new(self.key[:24], _D3.MODE_CBC, self.iv[:8])
        return self._unpad(c.decrypt(ciphertext))

    # ---------------- RC4 ----------------
    def rc4(self, ciphertext: bytes) -> bytes:
        """RC4 / ARC4. IV tidak dipakai (stream)."""
        if not HAS_PYCrypto:
            return b""
        from Crypto.Cipher import ARC4 as _RC4
        return _RC4.new(self.key).decrypt(ciphertext)

    # ---------------- padding helper ----------------
    def _unpad(self, pt: bytes) -> bytes:
        if self.pad == "pkcs7" and pt:
            n = pt[-1]
            if 0 < n <= 16 and pt[-n:] == bytes([n]) * n:
                return pt[:-n]
        return pt


# ==============================================================================
# 4. SALT & KDF (Key Derivation Function)
#    Banyak cipher "salt-based" memakai format:
#    "Salted__" + 8 byte salt + ciphertext  (format openssl klasik)
# ==============================================================================
class SaltKdf:
    """Bongkar format salted, lalu turunkan key/IV dari password via KDF."""

    MAGIC_OPENSSL = b"Salted__"

    @staticmethod
    def split_openssl_salt(data: bytes):
        """Kalau data diawali 'Salted__', kembalikan (salt, ciphertext).
        Kalau tidak, kembalikan (b"", data)."""
        if data.startswith(SaltKdf.MAGIC_OPENSSL) and len(data) >= 16:
            return data[8:16], data[16:]
        return b"", data

    # ---------------- (EVP_BytesToKey klasik openssl: md5) ----------------
    @staticmethod
    def evp_bytes_to_key(password: bytes, salt: bytes, key_len=32, iv_len=16,
                         hashfunc="md5", count=1):
        """Turunkan (key, iv) dari password+salt ala openssl -md md5.
        Ubah hashfunc/count utk -md sha256 dll."""
        key_iv = b""
        prev = b""
        algo = getattr(hashlib, hashfunc)
        while len(key_iv) < key_len + iv_len:
            prev = algo(prev + password + salt).digest()
            key_iv += prev
        return key_iv[:key_len], key_iv[key_len : key_len + iv_len]

    # ---------------- PBKDF2 (modern / OpenSSL >=1.1 dgn -iter) ----------------
    @staticmethod
    def pbkdf2(password: bytes, salt: bytes, key_len=32, iv_len=16,
               iterations=10000, hashfunc="sha256"):
        """Turunkan (key, iv) via PBKDF2-HMAC. gunakan utk cipher yg pakai -iter."""
        dk = hashlib.pbkdf2_hmac(hashfunc, password, salt, iterations, key_len + iv_len)
        return dk[:key_len], dk[key_len:]

    # ---------------- contoh: buka file salted AES-256-CBC ----------------
    def decrypt_salted_file(self, path: str, password: str, kdf="evp", **kw):
        """Template paling sering dipakai: file enkripsi openssl salted.
        `kdf`: 'evp' (klasik md5) atau 'pbkdf2' (modern)."""
        data = Util.read(path)
        salt, ct = self.split_openssl_salt(data)
        if kdf == "evp":
            key, iv = self.evp_bytes_to_key(password.encode(), salt, **kw)
        else:
            key, iv = self.pbkdf2(password.encode(), salt, **kw)
        dec = Symmetric(key, iv, mode="cbc")
        return dec.aes(ct, keysize=len(key))


# ==============================================================================
# 5. SSL / SERTIFIKAT / PEM / KUNCI RSA
# ==============================================================================
class SSL:
    """Urus sertifikat, kunci, PEM/DER, signature.

    Biasanya di challenge forensics: file .pem/.der/.key/.crt disembunyikan,
    atau flag terenkripsi dgn kunci publik RSA.
    """

    # ---------------- parse PEM/DER -> objek PKCS#8/1 ----------------
    def load_private_key(self, path: str):
        """Muat kunci privat RSA dari PEM atau DER. Password opsional."""
        data = Util.read(path)
        if HAS_PYCrypto:
            try:
                return RSA.import_key(data)
            except Exception:
                pass
        ### >>> ISI DI SINI: fallback load via cryptography / openssl
        return None

    # ---------------- RSA decrypt (private key) ----------------
    def rsa_decrypt(self, ciphertext: bytes, privkey_path: str,
                    oaep=True) -> bytes:
        """Decrypt RSA. `oaep`: True = PKCS1_OAEP, False = PKCS1_v1_5."""
        if not HAS_PYCrypto:
            return b""
        key = self.load_private_key(privkey_path)
        ciph = PKCS1_OAEP.new(key) if oaep else PKCS1_v1_5.new(key)
        return ciph.decrypt(ciphertext)

    # ---------------- RSA encrypt (public key) -> untuk test ----------------
    def rsa_encrypt(self, plaintext: bytes, pubkey_path: str, oaep=True) -> bytes:
        if not HAS_PYCrypto:
            return b""
        from Crypto.PublicKey import RSA as _R
        key = _R.import_key(Util.read(pubkey_path))
        ciph = PKCS1_OAEP.new(key) if oaep else PKCS1_v1_5.new(key)
        return ciph.encrypt(plaintext)

    # ---------------- parse x509 cert ----------------
    def cert_info(self, path: str):
        """Cetak info sertifikat X.509 (subject, issuer, validity, ext)."""
        ### >>> ISI DI SINI: parse via `openssl x509 -in file -text` (subprocess)
        ###   atau cryptography.x509. Contoh kasus: temukan flag di CN / SAN.
        pass  # TODO

    def pem_to_der(self, path: str, out: str = "out.der") -> None:
        """Konversi PEM -> DER."""
        ### >>> ISI DI SINI: base64-decode antara -----BEGIN/END-----.
        pass  # TODO

    def der_to_pem(self, path: str, out: str = "out.pem") -> None:
        """Konversi DER -> PEM (bungkus base64 + header)."""
        ### >>> ISI DI SINI: base64-encode + bungkus header PEM.
        pass  # TODO

    # ---------------- hash / signature ----------------
    def hash_file(self, path: str, algo="sha1") -> str:
        """Hitung hash file (untuk verifikasi integritas / cari file duplikat)."""
        h = hashlib.new(algo)
        h.update(Util.read(path))
        return h.hexdigest()


# ==============================================================================
# 6. AUTO-EXTRACT KEY / IV / SALT / PARAMETER (otak utamanya)
#    Tujuan: dari string/file berantakan, cari sendiri key & iv & salt.
# ==============================================================================
class AutoExtract:
    """Cari key/IV/salt/parameter secara otomatis dari konteks."""

    # pola umum label di script/strings: "key=...", "iv = ...", "salt: ..."
    PAT_KEY  = re.compile(rb"(?:key|k)\s*[=:]\s*([0-9a-fA-F]{16,64}|[A-Za-z0-9+/=]{8,})")
    PAT_IV   = re.compile(rb"(?:iv|init(?:-?vector)?)\s*[=:]\s*([0-9a-fA-F]{16,32})")
    PAT_SALT = re.compile(rb"(?:salt)\s*[=:]\s*([0-9a-fA-F]{2,16})")
    PAT_MODE = re.compile(rb"(?:mode|algo(?:rithm)?)\s*[=:]\s*([A-Za-z0-9-]+)")
    PAT_ITER = re.compile(rb"(?:iter(?:ations)?)\s*[=:]\s*(\d+)")

    @staticmethod
    def find(blob: bytes):
        """Scan blob (string/file) -> kembalikan dict hasil tebakan.
        Hasilkan: key, iv, salt, mode, iter, passphrase (yg paling mungkin)."""
        res = {"key": b"", "iv": b"", "salt": b"", "mode": "cbc",
               "iter": 10000, "passphrase": b"", "hints": []}

        def first(pat):
            m = pat.search(blob)
            return m.group(1) if m else b""

        # key: coba hex dulu, lalu base64, lalu string
        k = first(AutoExtract.PAT_KEY)
        if k:
            if Util.is_hex(k.decode("ascii", "ignore")):
                res["key"] = Util.hex_to_bytes(k.decode("ascii", "ignore"))
            else:
                ### >>> ISI DI SINI: coba base64 decode, kalau printable = key.
                res["key"] = k
            res["hints"].append("key")

        iv = first(AutoExtract.PAT_IV)
        if iv:
            res["iv"] = Util.hex_to_bytes(iv.decode("ascii", "ignore"))
            res["hints"].append("iv")

        salt = first(AutoExtract.PAT_SALT)
        if salt:
            res["salt"] = Util.hex_to_bytes(salt.decode("ascii", "ignore"))
            res["hints"].append("salt")

        m = first(AutoExtract.PAT_MODE)
        if m:
            res["mode"] = m.decode("ascii").lower()
        it = first(AutoExtract.PAT_ITER)
        if it:
            res["iter"] = int(it.decode("ascii"))

        # passphrase: string panjang printable di sekitar kata 'password'
        ### >>> ISI DI SINI: regex buat "password ..." / "pass=..." -> passphrase.
        return res


# ==============================================================================
# 7. XOR (bruteforce & key panja) +  klasik lainnya
# ==============================================================================
class Xor:
    """XOR decrypt + bruteforce."""

    @staticmethod
    def xor(data: bytes, key: bytes) -> bytes:
        """XOR bytes dengan key (diulang)."""
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    @staticmethod
    def brute_single_byte(data: bytes, printable_only=True):
        """Coba semua key 1 byte; kembalikan kandidat plaintext."""
        res = []
        for k in range(256):
            pt = Xor.xor(data, bytes([k]))
            if (not printable_only) or Util.is_printable(pt):
                res.append((k, pt))
        return res

    @staticmethod
    def brute_multi_byte(data: bytes, max_len=4):
        """Bruteforce key pendek (2-4 byte) via frequency analysis.
        Skeleton: cocok utk challenge XOR berkey pendek."""
        ### >>> ISI DI SINI: hitung key length via Index of Coincidence,
        ###   lalu solve tiap posisi pakai frekuensi huruf.
        pass  # TODO


# ==============================================================================
# 8. ORCHESTRATOR UTAMA ====== (gabung semua; cukup ubah bagian yang perlu) =====
# ==============================================================================
class AutoDecoder:
    """Satu pintu masuk: input string/file -> coba semua kemungkinan.

    Cara pakai umum:
        d = AutoDecoder()
        d.load_string("...") / d.load_file("...")
        d.auto_detect()                       # tebak encoding/cipher
        d.try_everything()                    # coba semua decoder, tampilkan yg printable
        d.salted_file("file", "password")     # decrypt file openssl-salted
        d.ssl_rsa("enc.bin", "priv.pem")      # RSA decrypt
    """

    def __init__(self):
        self.enc = Encoding()
        self.sym = Symmetric()
        self.salt = SaltKdf()
        self.ssl = SSL()
        self.xor = Xor()

    # ---------------- input ----------------
    def load_string(self, s: str):
        self._input = s.encode("utf-8")
        return self

    def load_file(self, path: str):
        self._input = Util.read(path)
        return self

    # ---------------- auto-detect encoding ----------------
    def auto_detect(self):
        """Coba decode berbagai encoding, tampilkan yang printable."""
        data = self._input
        results = {}
        # 1) cek hex
        try:
            results["hex"] = Util.hex_to_bytes(data.decode("ascii"))
        except Exception:
            pass
        # 2) base64
        try:
            results["base64"] = base64.b64decode(data, validate=True)
        except Exception:
            pass
        # 3) base32
        try:
            results["base32"] = base64.b32decode(data)
        except Exception:
            pass
        # 4) url
        try:
            from urllib.parse import unquote_to_bytes
            results["url"] = unquote_to_bytes(data.decode("ascii"))
        except Exception:
            pass
        # 5) rot13
        results["rot13"] = Util.rot(data.decode("ascii", "ignore"), 13).encode()
        # 6) binary bits
        try:
            txt = data.decode("ascii").replace(" ", "")
            if set(txt) <= {"0", "1"}:
                results["bits"] = bytes(int(txt[i:i+8], 2) for i in range(0, len(txt), 8))
        except Exception:
            pass

        for name, out in results.items():
            if out and Util.is_printable(out):
                print(f"[+] {name:8} -> {out.decode('utf-8', 'ignore')!r}")
        return results

    # ---------------- coba SEMUA decoder ----------------
    def try_everything(self):
        """Jalankan semua decoder yang relevan; cetak hasil printable."""
        for name in ("base64", "base32", "hex", "rot13", "rot47", "url"):
            fn = getattr(self.enc, name, None)
            if not fn:
                continue
            try:
                out = fn(self._input) if name != "rot13" else fn(self._input)
                if out and Util.is_printable(out):
                    print(f"[+] {name:8} -> {out!r}")
            except Exception:
                pass

    # ---------------- salted openssl file ----------------
    def salted_file(self, path: str, password: str, kdf="evp", **kw):
        """Decrypt file openssl-salted. `kdf`: 'evp'|'pbkdf2'."""
        return self.salt.decrypt_salted_file(path, password, kdf=kdf, **kw)

    # ---------------- cari key/iv/salt otomatis -> decrypt ----------------
    def crack_with_auto_params(self, path: str, password: str = ""):
        """Buka file, auto-extract key/iv/salt dari konteks sekitarnya,
        lalu coba degate. Template paling fleksibel."""
        blob = Util.read(path)
        params = AutoExtract.find(blob)
        print("[*] Auto params:", {k: (v.hex() if isinstance(v, bytes) else v)
                                   for k, v in params.items()})
        # salt file? lalu turunkan key
        salt, ct = SaltKdf.split_openssl_salt(blob)
        if ct and password:
            key, iv = SaltKdf.evp_bytes_to_key(password.encode(), salt,
                                               key_len=32, iv_len=16)
            return Symmetric(key, iv, "cbc").aes(ct, keysize=32)
        # key/iv langsung?
        if params["key"]:
            return Symmetric(params["key"], params["iv"], params["mode"]).aes(ct or blob)
        return b""


# ==============================================================================
# 9. CLI MINIMAL (demo) — ubah sesuka hati
# ==============================================================================
def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        d = AutoDecoder()
        data = "U0FMVEVERVNLWUJVSUxERVIgT0s="  # base64 "SALTEDESKYBUILDER OK"
        print("Input:", data)
        d.load_string(data)
        d.auto_detect()
        return

    print(__doc__[:600])
    print("\nCara pakai cepat:\n"
          "  python3 template_decoder.py --demo\n"
          "Lalu buka kode & ubah fungsi sesuai kebutuhan (cari '### >>> ISI DI SINI').")


if __name__ == "__main__":
    main()
