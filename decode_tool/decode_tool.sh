#!/usr/bin/env bash
# =============================================================================
#  Decode & Decrypt Toolkit
#  --------------------------------------------------------------------------
#  Fitur:
#   - Auto-detect encoding umum (hex / base64 / base32 / base58 / url / rot)
#   - Cipher klasik dengan key: Caesar, ROT13/47, Vigenere, XOR (+ brute 1-byte)
#   - Cipher modern via openssl: AES-128/192/256 (ECB/CBC/CTR/CFB/OFB),
#     DES, 3DES, RC4, SM4 - dengan passphrase ATAU raw hex key (+IV)
#   - Token: JWT (decode + verifikasi HS*) & Fernet
#   - Identifikasi jenis hash
#   - Output binary disimpan ke decode_result/ (di folder tempat tool
#     dijalankan) + preview hexdump
#
#  Cara pakai:
#     ./decode_tool.sh                          -> menu interaktif
#     ./decode_tool.sh "ciphertext..."          -> auto-detect
#     ./decode_tool.sh <method> "<data>"        -> decode langsung
#     ./decode_tool.sh -k "<key>" <method> "<data>"
#     ./decode_tool.sh -k "<key>" -f <file> <method>
#     ./decode_tool.sh -k "<key>" -f <file> -o <outfile> aes-256-cbc
#
#  Method: base64 base32 base58 hex url html rot13 rot47 caesar vigenere
#          xor xorhex xor-bruteforce bin escape aes-128-ecb aes-192-cbc
#          aes-256-cbc aes-256-ctr aes-256-cfb aes-256-ofb des-cbc
#          des-ede3-cbc rc4 sm4-cbc jwt fernet hashid auto
#
#  Raw hex key (untuk cipher modern, selain passphrase):
#     export KEYHEX=<hex>  IVHEX=<hex>   ./decode_tool.sh aes-256-cbc "<data>"
#
#  Requirement: openssl, python3, xxd, base64, base32, tr
# =============================================================================

set -uo pipefail

# ----------------------------- KONFIGURASI --------------------------------
OPENSSL="openssl"
PY="python3"
OUTDIR_BASE="$(pwd)/decode_result"   # hasil disimpan di folder tempat tool dijalankan
STYLE="\e[1;36m"; RESET="\e[0m"
RED="\e[1;31m"; GRN="\e[1;32m"; YLW="\e[1;33m"; BLU="\e[1;34m"

# ----------------------------- UTILITAS -----------------------------------
say()  { echo -e "${STYLE}[*]${RESET} $*"; }
ok()   { echo -e "${GRN}[+]${RESET} $*"; }
warn() { echo -e "${YLW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[-]${RESET} $*"; }

need_check() {
  local missing=()
  for b in openssl python3 xxd base64 base32 tr; do
    command -v "$b" >/dev/null 2>&1 || missing+=("$b")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    err "Tidak ditemukan: ${missing[*]}"
    exit 1
  fi
}

# ----------------------------- VARIABEL GLOBAL ----------------------------
KEY=""          # passphrase / key string
KEYHEX="${KEYHEX:-}"   # raw hex key (dari env KEYHEX atau menu)
IVHEX="${IVHEX:-}"     # raw hex IV (dari env IVHEX atau menu)
DATA=""         # input string
DATA_FILE=""    # input file
OUTFILE=""      # output file opsional
METHOD=""
OUTDIR="$OUTDIR_BASE/dec_$$"
LASTOUT="$OUTDIR/last.out"

ensure_outdir() {
  mkdir -p "$OUTDIR" 2>/dev/null
}

# feed -> kirim data input ke stdout (file atau string)
feed() {
  if [[ -n "$DATA_FILE" ]]; then
    cat "$DATA_FILE"
  else
    printf '%s' "$DATA"
  fi
}

# Persentase keterbacaan output (0-100), baca dari stdin
py_score() {
  "$PY" -c '
import sys
b = sys.stdin.buffer.read()
if not b:
    sys.exit(0)
good = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
print(min(100, good * 130 // len(b)))
'
}

# emit <label>: simpan hasil ke $LASTOUT lalu tampilkan (text / hexdump)
emit() {
  local label="$1" sz pr
  cat > "$LASTOUT"
  sz=$(stat -c%s "$LASTOUT" 2>/dev/null || echo 0)
  if (( sz > 0 )); then
    pr=$(py_score < "$LASTOUT")
    if (( pr >= 60 )); then
      cat "$LASTOUT"
      echo ""
    else
      warn "Output tampak binary ($pr% printable, ${sz} bytes) - preview hexdump:"
      xxd -l 512 "$LASTOUT" | head -24
    fi
  else
    err "Hasil kosong (mungkin key / padding / format salah)."
  fi
  ok "Output tersimpan: $LASTOUT"
}

# --------------------------- EMBEDDED PYTHON ------------------------------
# Skrip python dikirim via -c, stdin tetap bebas untuk data input.
# Data -> stdin, arg -> argv.

py_b64() {  # base64 tolerant (abaikan spasi, perbaiki padding)
  "$PY" -c "$(cat <<'PY'
import sys, base64
s = "".join(sys.stdin.read().split())
s += "=" * (-len(s) % 4)
sys.stdout.buffer.write(base64.b64decode(s, validate=False))
PY
)"
}

py_b32() {
  "$PY" -c "$(cat <<'PY'
import sys, base64, binascii
s = "".join(sys.stdin.read().split()).upper()
s += "=" * (-len(s) % 8)
try:
    sys.stdout.buffer.write(base64.b32decode(s, casefold=True))
except (binascii.Error, ValueError):
    sys.exit("bukan base32 valid")
PY
)"
}

py_b58() {
  "$PY" -c "$(cat <<'PY'
import sys
ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
s = "".join(sys.stdin.read().split())
try:
    n = 0
    for c in s:
        n = n * 58 + ALPHA.index(c)
except ValueError:
    sys.exit("bukan base58 valid")
b = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
lead = len(s) - len(s.lstrip("1"))
sys.stdout.buffer.write(b"\x00" * lead + b)
PY
)"
}

py_hex() {  # hex tolerant: 0x / spasi / colon diabaikan, ganjil di-pad 0
  "$PY" -c "$(cat <<'PY'
import sys, binascii
h = "".join(sys.stdin.read().split())
h = h.replace("0x", "").replace("0X", "")
if len(h) % 2:
    h = "0" + h
try:
    sys.stdout.buffer.write(binascii.unhexlify(h))
except (binascii.Error, ValueError):
    sys.exit("bukan hex valid")
PY
)"
}

py_url() {
  "$PY" -c "$(cat <<'PY'
import sys
from urllib.parse import unquote_to_bytes
sys.stdout.buffer.write(unquote_to_bytes(sys.stdin.read()))
PY
)"
}

py_html() {
  "$PY" -c "$(cat <<'PY'
import sys, html
sys.stdout.write(html.unescape(sys.stdin.read()))
PY
)"
}

py_rot47() {
  "$PY" -c "$(cat <<'PY'
import sys
data = sys.stdin.read()
sys.stdout.write("".join(
    chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c
    for c in data))
PY
)"
}

py_caesar() { # py_caesar <shift>  - key = shift enkripsi, decode = kurangi
  local shift="$1"
  "$PY" -c "$(cat <<'PY'
import sys
k = int(sys.argv[1])
out = []
for c in sys.stdin.read():
    if "a" <= c <= "z":
        out.append(chr((ord(c) - 97 - k) % 26 + 97))
    elif "A" <= c <= "Z":
        out.append(chr((ord(c) - 65 - k) % 26 + 65))
    else:
        out.append(c)
sys.stdout.write("".join(out))
PY
)" "$shift"
}

py_vigenere() { # py_vigenere <key>  - dekripsi = kurangi shift key
  local key="$1"
  "$PY" -c "$(cat <<'PY'
import sys
key = sys.argv[1].upper()
ki = 0
out = []
for c in sys.stdin.read():
    if "a" <= c <= "z":
        out.append(chr((ord(c) - 97 - (ord(key[ki]) - 65)) % 26 + 97))
        ki = (ki + 1) % len(key)
    elif "A" <= c <= "Z":
        out.append(chr((ord(c) - 65 - (ord(key[ki]) - 65)) % 26 + 65))
        ki = (ki + 1) % len(key)
    else:
        out.append(c)
sys.stdout.write("".join(out))
PY
)" "$key"
}

# py_xor <key> [hexmode]  - key string biasa atau 0x..., data hex bila hexmode=1
py_xor() {
  local key="$1" hexmode="${2:-0}"
  "$PY" -c "$(cat <<'PY'
import sys
key = sys.argv[1]
hexmode = sys.argv[2] == "1"
data = sys.stdin.buffer.read()
if hexmode:
    data = bytes.fromhex(data.decode().replace("0x", "").replace(" ", ""))
if key.startswith(("0x", "0X")):
    kb = bytes.fromhex(key[2:])
else:
    kb = key.encode()
sys.stdout.buffer.write(bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data)))
PY
)" "$key" "$hexmode"
}

py_xor_brute() {  # brute single-byte key; input hex otomatis di-decode
  "$PY" -c "$(cat <<'PY'
import sys
raw = sys.stdin.buffer.read().decode(errors="replace").strip()
if len(raw) % 2 == 0 and len(raw) >= 4 and all(c in "0123456789abcdefABCDEF" for c in raw):
    data = bytes.fromhex(raw)
else:
    data = raw.encode()
if not data:
    sys.exit(0)
res = []
for k in range(256):
    out = bytes(x ^ k for x in data)
    good = sum(1 for x in out if 32 <= x < 127)
    letters = sum(1 for x in out if 65 <= x <= 90 or 97 <= x <= 122 or x == 32)
    r, l = good / len(out), letters / len(out)
    if r >= 0.9 and l >= 0.5:
        res.append((r + l, k, out))
res.sort(reverse=True)
if not res:
    sys.stdout.write("(tidak ada kandidat kuat - cek apakah input benar plaintext ter-XOR)\n")
for _, k, out in res[:5]:
    sys.stdout.write("--- key 0x%02x ('%s') ---\n" % (k, chr(k) if 32 <= k < 127 else "."))
    sys.stdout.buffer.write(out[:300])
    sys.stdout.write("\n")
    sys.stdout.flush()
PY
)"
}

py_bin() {  # binary 8-bit (boleh spasi/pemisah)
  "$PY" -c "$(cat <<'PY'
import sys
s = "".join(sys.stdin.read().split())
s = s.replace("0b", "")
if len(s) % 8:
    sys.exit("jumlah bit bukan kelipatan 8")
try:
    out = bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8))
    sys.stdout.buffer.write(out)
except ValueError:
    sys.exit("bukan binary valid")
PY
)"
}

py_escape() {  # \xXX \uXXXX \NNN octal \n \t \r
  "$PY" -c "$(cat <<'PY'
import sys, re
s = sys.stdin.read().strip()
def rep(m):
    g = m.group(0)
    if g.startswith("\\x") or g.startswith("\\u") or g.startswith("\\U"):
        return chr(int(g[2:], 16))
    if g.startswith("\\0"):
        return chr(int(g[1:], 8))
    return {"\\n": "\n", "\\t": "\t", "\\r": "\r", "\\a": "\a", "\\b": "\b"}.get(g, g)
out = re.sub(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|\\0[0-7]{1,3}|\\n|\\t|\\r|\\a|\\b", rep, s)
sys.stdout.write(out)
PY
)"
}

py_jwt() {  # py_jwt <token> <key(optional)>
  local token="$1" key="${2:-}"
  "$PY" -c "$(cat <<'PY'
import sys, base64, json, hmac, hashlib
tok, key = sys.argv[1], sys.argv[2]
parts = tok.split(".")
if len(parts) not in (2, 3):
    sys.exit("Bukan format JWT (harus 2-3 segmen dipisah titik)")
def b64d(s):
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)
try:
    header = json.loads(b64d(parts[0]))
    payload = json.loads(b64d(parts[1]))
except Exception:
    sys.exit("Header/payload bukan JSON valid (token rusak?)")
print("== HEADER ==")
print(json.dumps(header, indent=2))
print("== PAYLOAD ==")
print(json.dumps(payload, indent=2))
if len(parts) == 3:
    alg = header.get("alg", "")
    if alg.startswith("HS") and key:
        h = getattr(hashlib, alg[2:].lower(), hashlib.sha256)
        sig = hmac.new(key.encode(), (parts[0] + "." + parts[1]).encode(), h).digest()
        expect = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        match = hmac.compare_digest(expect, parts[2])
        print("== SIGNATURE (HS* dengan key) ==")
        print("valid" if match else "INVALID (key salah / token diubah)")
    elif alg.startswith("HS"):
        print("== SIGNATURE ==")
        print("tidak diverifikasi - beri key via -k atau menu")
    else:
        print("== SIGNATURE ==")
        print("algoritma %s (asimetris) - hanya decode, verifikasi butuh pubkey" % alg)
PY
)" "$token" "$key"
}

py_fernet() {  # py_fernet <key urlsafe-b64> <token>
  local key="$1" token="$2"
  "$PY" -c "$(cat <<'PY'
import sys
try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    sys.exit("library 'cryptography' tidak terpasang (pip install cryptography)")
key, token = sys.argv[1], sys.argv[2]
if token.startswith("b'") and token.endswith("'"):
    token = token[2:-1]   # strip repr python b'...'
f = Fernet(key.encode())
try:
    pt = f.decrypt(token.encode())
    sys.stdout.buffer.write(pt)
except InvalidToken:
    sys.exit("INVALID token - key salah atau token rusak/kedaluwarsa")
PY
)" "$key" "$token"
}

py_hashid() {  # identifikasi jenis hash by pola
  "$PY" -c "$(cat <<'PY'
import sys, re
h = sys.stdin.read().strip()
if not h:
    sys.exit()
low = h.lower()
def out(s): print("Kemungkinan:", s)
if re.fullmatch(r"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}", h):
    out("bcrypt ($2a/$2b/$2y$)")
elif re.fullmatch(r"\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}", h):
    out("md5crypt ($1$)")
elif re.fullmatch(r"\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}", h):
    out("sha256crypt ($5$)")
elif re.fullmatch(r"\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}", h):
    out("sha512crypt ($6$)")
elif h.startswith("$argon2"):
    out("Argon2 (argon2id / argon2i)")
elif h.startswith("pbkdf2"):
    out("PBKDF2 (format Django)")
elif len(h) == 32 and re.fullmatch(r"[0-9a-f]{32}", h):
    out("md5 / NTLM / MySQL4.x (panjang sama; butuh konteks tambahan)")
elif len(h) == 32 and re.fullmatch(r"[0-9A-F]{32}", h):
    out("LM hash (Windows) / NTLM")
elif len(h) == 40 and re.fullmatch(r"[0-9a-f]{40}", low):
    out("SHA-1")
elif len(h) == 56 and re.fullmatch(r"[0-9a-f]{56}", low):
    out("SHA-224")
elif len(h) == 64 and re.fullmatch(r"[0-9a-f]{64}", low):
    out("SHA-256 / SHA3-256")
elif len(h) == 96 and re.fullmatch(r"[0-9a-f]{96}", low):
    out("SHA-384")
elif len(h) == 128 and re.fullmatch(r"[0-9a-f]{128}", low):
    out("SHA-512 / Whirlpool")
elif len(h) == 16 and re.fullmatch(r"[0-9a-f]{16}", low):
    out("MySQL pre-4.1 / DES / CRC64 (pendek)")
elif re.fullmatch(r"\{SHA\}[A-Za-z0-9+/=]{28}", h):
    out("Apache {SHA} (SHA-1) base64")
elif re.fullmatch(r"\{SSHA\}[A-Za-z0-9+/=]{28,}", h):
    out("Apache {SSHA} salted")
elif re.fullmatch(r"\{MD5\}[A-Za-z0-9+/=]{22,}", h):
    out("Apache {MD5}")
elif re.fullmatch(r"\d+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]*:[0-9]+:[0-9a-f]+", low):
    out("Shadow (unix): user:hash:...")
elif len(h) == 88 and re.fullmatch(r"[A-Za-z0-9+/=]{88}", h):
    out("SHA-512 base64 (crypt) / Windows DPAPI blob")
else:
    out("tidak dikenal - hash modern dengan salt tidak bisa ditebak dari panjang saja")
print()
print("Catatan: hash = one-way. Tools ini hanya MENGIDENTIFIKASI tipe,")
print("bukan mendekripsi. Untuk crack gunakan: hashcat / john / hydra.")
PY
)"
}

# ------------------------------- DECODER ----------------------------------
# Tiap decoder: baca dari feed() -> tulis ke emit()

dec_base64()    { feed | py_b64 | emit "base64"; }
dec_base32()    { feed | py_b32 | emit "base32"; }
dec_base58()    { feed | py_b58 | emit "base58"; }
dec_hex()       { feed | py_hex | emit "hex"; }
dec_url()       { feed | py_url | emit "URL percent-encoded"; }
dec_html()      { feed | py_html | emit "HTML-unescape"; }
dec_rot13()     { feed | tr 'A-Za-z' 'N-ZA-Mn-za-m' | emit "ROT13"; }
dec_rot47()     { feed | py_rot47 | emit "ROT47"; }
dec_bin()       { feed | py_bin | emit "binary 8-bit"; }
dec_escape()    { feed | py_escape | emit "escape sequence"; }

dec_caesar() {
  local shift="$KEY"
  if [[ -z "$shift" && -n "$DATA" && "$DATA" =~ ^-?[0-9]+$ ]]; then
    shift="$DATA"  # ./decode_tool.sh caesar "3" -> data numerik = shift
    DATA=""
  fi
  if [[ -z "$shift" ]]; then
    read -rp "Shift (0-25) atau kosong untuk coba semua: " shift
  fi
  if [[ -z "$shift" ]]; then
    local i out score
    for i in $(seq 0 25); do
      out=$(feed | py_caesar "$i")
      score=$(printf '%s' "$out" | py_score)
      if (( score >= 60 )); then
        ok "Shift $i (score $score%):"
        printf '%s\n' "$out"
      fi
    done
  else
    feed | py_caesar "$shift" | emit "Caesar shift $shift"
  fi
}

dec_vigenere() {
  local key="$KEY"
  if [[ -z "$key" ]]; then
    read -rp "Key Vigenere (hanya huruf): " key
  fi
  [[ -z "$key" ]] && { err "Key kosong."; return 1; }
  feed | py_vigenere "$key" | emit "Vigenere"
}

need_xor_key() {
  [[ -n "$KEY" ]] && return 0
  read -rp "Key XOR (string atau 0x-hex): " KEY
  [[ -n "$KEY" ]]
}

dec_xor() {
  need_xor_key || { err "Key XOR kosong."; return 1; }
  local hexchars="${DATA//[^0-9a-fA-F]/}"
  if [[ -z "$DATA_FILE" && -n "$hexchars" && "$DATA" =~ ^[0-9a-fA-F[:space:]]+$ ]] && (( ${#hexchars} % 2 == 0 )); then
    warn "Input murni hex (${#hexchars} digit) - di-auto-decode sebagai hex."
    feed | py_xor "$KEY" 1 | emit "XOR (auto hex)"
  else
    feed | py_xor "$KEY" | emit "XOR"
  fi
}

dec_xorhex() {
  need_xor_key || { err "Key XOR kosong."; return 1; }
  feed | py_xor "$KEY" 1 | emit "XOR (input hex)"
}

dec_xor_brute() {
  feed | py_xor_brute | emit "XOR brute 1-byte"
}

# openssl_run <cipher> - implementasi umum untuk cipher symetric
openssl_run() {
  local cipher="$1" digest_note=""
  [[ -n "$KEYHEX" ]] && digest_note=" (raw hex key/iv)"
  local args=(-d "-$cipher")
  if [[ -n "$KEYHEX" ]]; then
    args+=(-K "$KEYHEX")
    [[ -n "$IVHEX" ]] && args+=(-iv "$IVHEX")
  else
    if [[ -z "$KEY" ]]; then
      read -rsp "Passphrase: " KEY; echo ""
    fi
    [[ -z "$KEY" ]] && { err "Passphrase kosong."; return 1; }
    args+=(-pass "pass:$KEY" -pbkdf2)
  fi
  if [[ -n "$DATA_FILE" ]]; then
    args+=(-in "$DATA_FILE")
  fi
  # Deteksi input base64 vs raw: jika hanya karakter b64 -> pakai -a -A
  local probe=""
  if [[ -n "$DATA_FILE" ]]; then
    probe=$(head -c 512 "$DATA_FILE" 2>/dev/null)
  else
    probe="$DATA"
  fi
  if [[ -n "$probe" ]] && ! printf '%s' "$probe" | grep -aqE '[^A-Za-z0-9+/=[:space:]]'; then
    args+=(-a -A)
  fi
  local outbin="$OUTDIR/dec_${cipher}_$$.bin"
  say "openssl enc -d $cipher (input: ${DATA_FILE:-base64 string})"
  local cmd=( "$OPENSSL" enc "${args[@]}" )
  local rc
  if [[ -n "$DATA_FILE" ]]; then
    "${cmd[@]}" > "$outbin" 2> "$OUTDIR/openssl.err"
  else
    feed | "${cmd[@]}" > "$outbin" 2> "$OUTDIR/openssl.err"
  fi
  rc=$?
  if (( rc == 0 )); then
    ok "Decrypt sukses$digest_note"
    cat "$outbin" | emit "openssl $cipher"
  elif [[ "$cipher" == rc4* ]]; then
    # OpenSSL 3: RC4 masuk legacy provider - coba ulang dengan provider tsb
    cmd=( "$OPENSSL" -provider legacy -provider default enc "${args[@]}" )
    if [[ -n "$DATA_FILE" ]]; then
      "${cmd[@]}" > "$outbin" 2> "$OUTDIR/openssl.err"
    else
      feed | "${cmd[@]}" > "$outbin" 2> "$OUTDIR/openssl.err"
    fi
    if (( $? == 0 )); then
      ok "Decrypt sukses (legacy provider)$digest_note"
      cat "$outbin" | emit "openssl $cipher"
    else
      err "Decrypt gagal:"
      cat "$OUTDIR/openssl.err" | head -3
      warn "Kemungkinan: passphrase/key salah, IV salah, atau cipher & mode tidak cocok."
    fi
  else
    err "Decrypt gagal:"
    cat "$OUTDIR/openssl.err" | head -3
    warn "Kemungkinan: passphrase/key salah, IV salah, atau cipher & mode tidak cocok."
  fi
}

dec_openssl() {
  case "$METHOD" in
    aes-128-ecb) openssl_run aes-128-ecb ;;
    aes-192-cbc) openssl_run aes-192-cbc ;;
    aes-256-cbc) openssl_run aes-256-cbc ;;
    aes-256-ctr) openssl_run aes-256-ctr ;;
    aes-256-cfb) openssl_run aes-256-cfb ;;
    aes-256-ofb) openssl_run aes-256-ofb ;;
    des-cbc)     openssl_run des-cbc ;;
    des-ede3-cbc) openssl_run des-ede3-cbc ;;
    rc4)         openssl_run rc4 ;;
    sm4-cbc)     openssl_run sm4-cbc ;;
    *) err "Cipher tidak dikenal: $METHOD" ;;
  esac
}

dec_jwt() {
  local token="$DATA" key="$KEY"
  if [[ -z "$token" ]]; then
    read -rp "Token JWT: " token
  fi
  if [[ -z "$key" ]]; then
    read -rp "Key untuk verifikasi HS* (kosong = decode saja): " key
  fi
  [[ -z "$token" ]] && { err "Token kosong."; return 1; }
  py_jwt "$token" "$key" | emit "JWT"
}

dec_fernet() {
  local token="$DATA" key="$KEY"
  if [[ -z "$token" ]]; then
    read -rp "Token Fernet: " token
  fi
  if [[ -z "$key" ]]; then
    read -rp "Key Fernet (32-byte urlsafe b64): " key
  fi
  [[ -z "$token" || -z "$key" ]] && { err "Token/key kosong."; return 1; }
  py_fernet "$key" "$token" | emit "Fernet"
}

dec_hashid() {
  local h="$DATA"
  [[ -z "$h" && -z "$DATA_FILE" ]] && read -rp "Hash: " h
  if [[ -n "$h" ]]; then
    printf '%s\n' "$h" | py_hashid
  else
    feed | py_hashid
  fi
}

# Auto-detect: coba semua encoding, tampilkan 2 kandidat terbaik
dec_auto() {
  local name dec out score best1="" best2="" sc nm ob c1=0 c2=0
  local tries=(
    "hex:py_hex"
    "base64:py_b64"
    "base32:py_b32"
    "base58:py_b58"
    "url:py_url"
    "rot13:tr"
    "rot47:py_rot47"
    "binary:py_bin"
    "escape:py_escape"
  )
  echo ""
  say "Auto-detect $([ -n "$DATA_FILE" ] && echo "file: $DATA_FILE" || echo "string: ${DATA:0:60}...")"
  for t in "${tries[@]}"; do
    name="${t%%:*}"; dec="${t##*:}"
    case "$dec" in
      tr) out=$(feed | tr 'A-Za-z' 'N-ZA-Mn-za-m' | head -c 400);;
      *)  out=$(feed | "$dec" 2>/dev/null | head -c 400);;
    esac
    [[ -z "$out" ]] && continue
    score=$(printf '%s' "$out" | py_score)
    if (( score >= 60 )); then
      if (( score > c1 )); then
        best2="$best1"; c2="$c1"
        best1="$score|$name|$out"; c1="$score"
      elif (( score > c2 )); then
        best2="$score|$name|$out"; c2="$score"
      fi
    fi
  done
  if [[ -n "$best1" ]]; then
    IFS='|' read -r sc nm ob <<< "$best1"
    ok "[$nm] (score $sc%)"; printf '  %s\n' "$ob" | head -2; echo ""
  fi
  if [[ -n "$best2" ]]; then
    IFS='|' read -r sc nm ob <<< "$best2"
    ok "[$nm] (score $sc%)"; printf '  %s\n' "$ob" | head -2; echo ""
  fi
  warn "Jika tidak ada hasil: coba method specifik dengan key (aes / vigenere / xor / jwt...)."
}

# ------------------------------- DISPATCH ---------------------------------
is_method() {
  local m
  for m in base64 base32 base58 hex url html rot13 rot47 caesar vigenere \
           xor xorhex xor-bruteforce bin escape aes-128-ecb aes-192-cbc \
           aes-256-cbc aes-256-ctr aes-256-cfb aes-256-ofb des-cbc \
           des-ede3-cbc rc4 sm4-cbc jwt fernet hashid auto; do
    [[ "$1" == "$m" ]] && return 0
  done
  return 1
}

# pastikan ada data (string/file/stdin)
ensure_data() {
  if [[ -n "$DATA" || -n "$DATA_FILE" ]]; then
    return 0
  fi
  if [[ ! -t 0 ]]; then
    DATA="$(cat)"
    return 0
  fi
  read -rp "Masukkan string ciphertext (atau ':filename' untuk baca file): " DATA
  if [[ "$DATA" == :* ]]; then
    DATA_FILE="${DATA#:}"
    DATA=""
  fi
}

dispatch() {
  local m="$1"
  case "$m" in
    auto)   ensure_data; dec_auto;;
    base64) ensure_data; dec_base64;;
    base32) ensure_data; dec_base32;;
    base58) ensure_data; dec_base58;;
    hex)    ensure_data; dec_hex;;
    url)    ensure_data; dec_url;;
    html)   ensure_data; dec_html;;
    rot13)  ensure_data; dec_rot13;;
    rot47)  ensure_data; dec_rot47;;
    bin)    ensure_data; dec_bin;;
    escape) ensure_data; dec_escape;;
    caesar) ensure_data; dec_caesar;;
    vigenere) ensure_data; dec_vigenere;;
    xor)      ensure_data; dec_xor;;
    xorhex)   ensure_data; dec_xorhex;;
    xor-bruteforce) ensure_data; dec_xor_brute;;
    aes-*|des-*|rc4|sm4-*) ensure_data; dec_openssl;;
    jwt)    ensure_data; dec_jwt;;
    fernet) ensure_data; dec_fernet;;
    hashid) ensure_data; dec_hashid;;
    *) err "Method tidak dikenal: $m"; usage;;
  esac
  if [[ -n "$OUTFILE" && -f "$LASTOUT" ]]; then
    cp "$LASTOUT" "$OUTFILE" && ok "Salinan output: $OUTFILE"
  fi
}

# -------------------------------- MENU ------------------------------------
menu_aes() {
  echo ""
  echo "  AES (openssl):"
  echo "    1) AES-128-ECB    2) AES-192-CBC    3) AES-256-CBC"
  echo "    4) AES-256-CTR    5) AES-256-CFB    6) AES-256-OFB"
  read -rp "  Pilih: " s
  case "$s" in
    1) METHOD=aes-128-ecb;; 2) METHOD=aes-192-cbc;; 3) METHOD=aes-256-cbc;;
    4) METHOD=aes-256-ctr;; 5) METHOD=aes-256-cfb;; 6) METHOD=aes-256-ofb;;
    *) warn "Batal"; return 1;;
  esac
  menu_key_mode
  dec_openssl
}

menu_des() {
  echo ""
  echo "  DES / 3DES / RC4 / SM4 (openssl):"
  echo "    1) DES-CBC    2) 3DES (EDE3-CBC)    3) RC4    4) SM4-CBC"
  read -rp "  Pilih: " s
  case "$s" in
    1) METHOD=des-cbc;; 2) METHOD=des-ede3-cbc;; 3) METHOD=rc4;; 4) METHOD=sm4-cbc;;
    *) warn "Batal"; return 1;;
  esac
  menu_key_mode
  dec_openssl
}

menu_key_mode() {
  echo ""
  echo "  Mode key:"
  echo "    1) Passphrase (openssl -pbkdf2)"
  echo "    2) Raw hex key (+IV)"
  read -rp "  Pilih [1]: " km
  if [[ "$km" == "2" ]]; then
    read -rp "  KEYHEX (hex): " KEYHEX
    read -rp "  IVHEX   (hex, opsional): " IVHEX
    KEY=""
  else
    KEYHEX=""; IVHEX=""
    read -rsp "  Passphrase: " KEY; echo ""
  fi
}

menu_input() {
  read -rp "Masukkan string ciphertext (atau ':filename'): " DATA
  if [[ "$DATA" == :* ]]; then
    DATA_FILE="${DATA#:}"; DATA=""
    ok "Input file: $DATA_FILE"
  else
    DATA_FILE=""
    ok "Input string: ${DATA:0:50}..."
  fi
}

main_menu() {
  local m
  while true; do
    echo ""
    echo "======================================================================"
    echo -e "  ${STYLE}Decode & Decrypt Toolkit${RESET}"
    echo "======================================================================"
    if [[ -n "$DATA_FILE" ]]; then
      echo -e "  Input : ${GRN}file: $DATA_FILE${RESET}"
    else
      echo -e "  Input : ${GRN}${DATA:0:60}${RESET}"
    fi
    echo -e "  Outdir: ${BLU}${OUTDIR}${RESET}"
    echo "----------------------------------------------------------------------"
    echo "  1) Auto-detect encoding            2) base64 / base32 / base58"
    echo "  3) hex                             4) URL percent / HTML entities"
    echo "  5) binary / escape sequence        6) ROT13 / ROT47"
    echo "  7) Caesar (shift)                  8) Vigenere"
    echo "  9) XOR (key)                      10) XOR bruteforce 1-byte"
    echo " 11) AES (openssl)                  12) DES / 3DES / RC4 / SM4"
    echo " 13) JWT decode+verify              14) Fernet"
    echo " 15) Identifikasi hash"
    echo "----------------------------------------------------------------------"
    echo "  I) Ganti input   L) Lihat input   Q) Keluar"
    echo "----------------------------------------------------------------------"
    read -rp "Pilih menu: " m
    case "$m" in
      1) ensure_data; dec_auto;;
      2) echo "  sub: 1) base64  2) base32  3) base58"; read -rp "  Pilih: " sm
         case "$sm" in 1) ensure_data; dec_base64;; 2) ensure_data; dec_base32;; 3) ensure_data; dec_base58;; *) warn "Batal";; esac;;
      3) ensure_data; dec_hex;;
      4) echo "  sub: 1) URL percent  2) HTML entities"; read -rp "  Pilih: " sm
         case "$sm" in 1) ensure_data; dec_url;; 2) ensure_data; dec_html;; *) warn "Batal";; esac;;
      5) ensure_data
         echo "  sub: 1) binary 8-bit  2) escape \\x \\u \\0NNN"; read -rp "  Pilih: " sm
         case "$sm" in 1) dec_bin;; 2) dec_escape;; *) warn "Batal";; esac;;
      6) ensure_data
         echo "  sub: 1) ROT13  2) ROT47"; read -rp "  Pilih: " sm
         case "$sm" in 1) dec_rot13;; 2) dec_rot47;; *) warn "Batal";; esac;;
      7) ensure_data; dec_caesar;;
      8) ensure_data; dec_vigenere;;
      9) ensure_data
         echo "  XOR key: 1) input teks  2) input hex"; read -rp "  Pilih [1]: " xm
         case "$xm" in 2) dec_xorhex;; *) dec_xor;; esac;;
     10) ensure_data; dec_xor_brute;;
     11) ensure_data; menu_aes;;
     12) ensure_data; menu_des;;
     13) dec_jwt;;
     14) dec_fernet;;
     15) dec_hashid;;
      [iI]) menu_input;;
      [lL]) echo "---"; if [[ -n "$DATA_FILE" ]]; then cat "$DATA_FILE"; else printf '%s\n' "$DATA"; fi; echo "---";;
      [qQ]) exit 0;;
      *) warn "Pilihan tidak dikenal: $m";;
    esac
  done
}

usage() {
  echo ""
  echo "Cara pakai:"
  echo "  $0                                   -> menu interaktif"
  echo "  $0 \"ciphertext...\"                   -> auto-detect"
  echo "  $0 <method> \"<data>\"                 -> decode langsung"
  echo "  $0 -k \"<key>\" <method> \"<data>\"     -> dengan key"
  echo "  $0 -k \"<key>\" -f <file> <method>    -> input dari file"
  echo "  $0 -k \"<key>\" -f <file> -o <out> <method>"
  echo ""
  echo "Method: base64 base32 base58 hex url html rot13 rot47 caesar"
  echo "        vigenere xor xorhex xor-bruteforce bin escape aes-128-ecb"
  echo "        aes-192-cbc aes-256-cbc aes-256-ctr aes-256-cfb aes-256-ofb"
  echo "        des-cbc des-ede3-cbc rc4 sm4-cbc jwt fernet hashid auto"
  echo ""
  echo "Raw hex key: export KEYHEX=<hex> IVHEX=<hex>"
}

# ----------------------------- MAIN ---------------------------------------
main() {
  need_check
  ensure_outdir

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -k) KEY="${2:-}"; shift 2;;
      -f) DATA_FILE="${2:-}"; shift 2;;
      -o) OUTFILE="${2:-}"; shift 2;;
      -h|--help) usage; exit 0;;
      *) break;;
    esac
  done

  if [[ $# -gt 0 ]]; then
    local first="$1"
    if is_method "$first"; then
      METHOD="$first"
      shift
      DATA="${*:-}"
    else
      DATA="$*"        # arg pertama bukan method -> data untuk auto-detect
    fi
  fi

  if [[ -n "$METHOD" ]]; then
    dispatch "$METHOD"
  elif [[ -n "$DATA" || -n "$DATA_FILE" || ! -t 0 ]]; then
    ensure_data
    dec_auto
  else
    menu_input
    main_menu
  fi
}

main "$@"