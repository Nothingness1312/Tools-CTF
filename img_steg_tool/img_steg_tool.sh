#!/usr/bin/env bash
# =============================================================================
#  Image Steganography & Forensics Toolkit (PNG / JPG)
#  --------------------------------------------------------------------------
#  Fitur:
#   - Info dasar gambar (identify / file)
#   - Metadata EXIF (exiftool) + flag menarik (comment / GPS / copyright)
#   - String extraction (strings) + grep pola flag
#   - Embedded file / append data scan (binwalk) + ekstraksi volume (dd/carve)
#   - Steghide extract (dengan passphrase) + brute-force kata sandi
#   - LSB/MSB bitplane extraction per channel RGB(A) via python/numpy
#   - Visualisasi bitplane (disimpan ke file PNG) untuk inspeksi manual
#   - zsteg all-methods (PNG/BMP) & analisa DCT JPEG
#   - Output analisa tampilin langsung (hasil ekstrak ke folder img_result/)
#
#  Cara pakai:
#     ./img_steg_tool.sh                          -> menu interaktif (pilih file)
#     ./img_steg_tool.sh /path/img.png            -> pilih menu utk file tersebut
#     ./img_steg_tool.sh /path/img.png auto        -> langsung semua scan umum
#     ./img_steg_tool.sh -p "pass" /path/img.png steghide
#     ./img_steg_tool.sh <FILE> <method>
#     ./img_steg_tool.sh <FILE> lsb    (coba channel R,G,B,Alpha - LSB)
#     ./img_steg_tool.sh <FILE> bitplane (dump ke-8 bit tiap channel ke PNG)
#     ./img_steg_tool.sh <FILE> full    (semua metode)
#
#  Method: auto info exif strings binwalk steghide steghide-brute
#          lsb lsb-msb bitplane zsteg jpeg carve full
#
#  Requirement: exiftool, binwalk, steghide, zsteg, imagemagick (identify),
#               python3 (numpy, PIL) optional utk LSB/bitplane
# =============================================================================

set -uo pipefail

# ----------------------------- KONFIGURASI --------------------------------
STYLE="\e[1;36m"; RESET="\e[0m"
RED="\e[1;31m"; GRN="\e[1;32m"; YLW="\e[1;33m"; BLU="\e[1;34m"

OUTDIR_BASE="$(pwd)/img_result"   # hasil disimpan di folder tool dijalankan
PASSPHRASE=""                      # passphrase steghide (opsional)
WORDLIST=""                        # wordlist utk brute steghide

# ----------------------------- UTILITAS -----------------------------------
say()  { echo -e "${STYLE}[*]${RESET} $*"; }
ok()   { echo -e "${GRN}[+]${RESET} $*"; }
warn() { echo -e "${YLW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[-]${RESET} $*"; }

# Path resolver: terima absolut atau relatif -> absolut
resolve() {
  local p="$1"
  if [[ "$p" != /* ]]; then
    p="$(pwd)/$p"
  fi
  echo "$p"
}

# ----------------------------- VARIABEL GLOBAL ----------------------------
IMAGE=""
METHOD=""
OUTDIR="$OUTDIR_BASE/img_$$"
LASTOUT=""

ensure_outdir() {
  mkdir -p "$OUTDIR" 2>/dev/null
}

# Cek apakah satu tool tersedia
have() {
  command -v "$1" >/dev/null 2>&1
}

# Cek sebuah tool, keluar dengan pesan bila tidak ada
need() {
  have "$1" || { err "Tool '$1' tidak ditemukan di PATH."; return 1; }
}

separator() {
  echo ""
  echo "----------------------------------------------------------------------"
}

# --------------------------- DETEKSI FORMAT -------------------------------

file_format() {
  file -b "$IMAGE" 2>/dev/null | cut -d, -f1
}

is_png() {
  [[ "$(file -b -m "$(file -b "$IMAGE")" "$IMAGE" 2>/dev/null | grep -io png)" != "" ]] && return 0
  file -b "$IMAGE" | grep -qi "PNG" && return 0
  return 1
}

is_jpeg() {
  file -b "$IMAGE" | grep -qi "JPEG" && return 0
  return 1
}

has_alpha() {
  identify -format "%[channels]" "$IMAGE" 2>/dev/null | grep -qi a
}

# ------------------------ 1) INFORMASI DASAR ------------------------------

run_info() {
  echo ""
  say "=== Info file ==="
  file "$IMAGE"
  echo ""
  say "=== ImageMagick identify ==="
  if have identify; then
    identify -verbose "$IMAGE" 2>/dev/null | head -40
  else
    warn "identify tidak ada - skip."
  fi
}

# ------------------------ 2) METADATA EXIF --------------------------------

run_exif() {
  clear
  echo ""
  say "=== Metadata EXIF (exiftool) ==="
  need exiftool || return 1
  exiftool "$IMAGE" 2>&1
  echo ""
  say "=== Flag menarik: komentar / deskripsi / author / GPS / copyright ==="
  local pat='Comment|Description|Title|Author|Creator|Artist|Copyright|GPS|UserComment|ImageDescription|Software|Make|Model|Thumbnail|Profile|XMP|MakerNote'
  exiftool "$IMAGE" 2>/dev/null | grep -iE "$pat" || warn "Tidak ada metadata mencurigakan ditemukan."
}

# ------------------------ 3) STRING EXTRACTION ----------------------------

run_strings() {
  clear
  echo ""
  say "=== String extraction (strings) ==="
  local pat="${STEG_STRING_PAT:-}"
  if [[ -z "$pat" ]]; then
    say "Mencari pola flag umum (flag/CTF/{...}/key/password/secret)..."
    strings -n 4 -a "$IMAGE" | grep -inE 'flag|ctf|picoctf|\{[^}]{8,}\}|password|secret|passwd|key[=:]|token|base64|http|ssh|BEGIN ' -A0 -B0 | head -40 || true
  else
    say "Mencari pola: $pat"
    strings -n 4 -a "$IMAGE" | grep -inE "$pat" | head -60 || true
  fi
  echo ""
  say "Cek trailing data (appended) setelah footer file:"
  check_trailing
}

# Deteksi data yang ditempel setelah akhir file asli (append)
check_trailing() {
  local footer_off="" end_off
  if is_png; then
    # IEND chunk = 00 00 00 00 49 45 4E 44 AE 42 60 82
    footer_off=$(grep -abo $'\x49\x45\x4e\x44\xae\x42\x60\x82' "$IMAGE" 2>/dev/null | head -1 | cut -d: -f1)
  elif is_jpeg; then
    # EOI marker FFD9 - cari byte terakhir
    :
  fi
  end_off=$(stat -c%s "$IMAGE")
  if [[ -n "$footer_off" ]]; then
    local tail=$(( end_off - footer_off - 8 ))
    if (( tail > 0 )); then
      ok "Terdeteksi ${tail} byte tambahan setelah IEND (append data)! offset: $((footer_off+8))"
      say "Preview 5 baris pertama trailing data:"
      tail -c "$tail" "$IMAGE" | strings -n 4 | head -5
      warn "Untuk ekstrak: gunakan menu 'carve' / 'dd' dari offset tsb."
    else
      ok "Tidak ada data setelah footer file (end of file sesuai)."
    fi
  else
    warn "Tidak bisa menentukan footer (format bukan PNG/JPEG standar)."
  fi
}

# ------------------------ 4) BINWALK SCAN ---------------------------------

run_binwalk() {
  clear
  echo ""
  say "=== Binwalk scan ==="
  need binwalk || return 1
  local out
  out=$(binwalk "$IMAGE" 2>&1)
  echo "$out" | grep -viE '^$'
  echo ""
  local n
  n=$(grep -cE '^\s*[0-9]+' <(grep -v '^DECIMAL' <<< "$out") 2>/dev/null || echo 0)
  if [[ "$n" -gt 0 ]]; then
    warn "Ditemukan ${n} signature. Jalankan 'carve' untuk mengekstrak file."
  else
    ok "Tidak ada embedded file signature ditemukan."
  fi
}

# ------------------------ 5) STEGHIDE -------------------------------------

run_steghide() {
  echo ""
  say "=== Steghide extract ==="
  need steghide || return 1
  local info
  # steghide info meminta konfirmasi "Try to get information about embedded
  # data ?" - jawab 'y' secara otomatis, dan beri passphrase bila diset.
  if [[ -n "$PASSPHRASE" ]]; then
    info=$(steghide info -p "$PASSPHRASE" "$IMAGE" 2>&1)
  else
    info=$(printf 'y\n' | steghide info "$IMAGE" 2>&1)
  fi
  echo "$info" | head -12
  echo "$info" > "$OUTDIR/steghide_info.txt"
  if echo "$info" | grep -qi 'embedded file'; then
    ok "steghide mendeteksi file tertanam di gambar ini."
  else
    warn "steghide info tidak melihat file tertanam (mungkin butuh passphrase, atau bukan stego steghide)."
  fi
  echo ""
  if [[ -n "$PASSPHRASE" ]]; then
    say "Mencoba ekstrak dengan passphrase: '$PASSPHRASE'"
    if steghide extract -sf "$IMAGE" -p "$PASSPHRASE" -xf "$OUTDIR/steghide.bin" </dev/null 2>/dev/null; then
      ok "SUKSES! File diekstrak ke: $OUTDIR/steghide.bin"
      file "$OUTDIR/steghide.bin"
    else
      err "Gagal - passphrase salah atau tidak ada data terenkripsi."
    fi
  else
    warn "Coba tanpa passphrase dulu, lalu dengan passphrase jika diminta."
    steghide extract -sf "$IMAGE" -xf "$OUTDIR/steghide.bin" </dev/null 2>&1 | head -5 || true
    if [[ -f "$OUTDIR/steghide.bin" && -s "$OUTDIR/steghide.bin" ]]; then
      ok "Berhasil tanpa passphrase -> $OUTDIR/steghide.bin"
      file "$OUTDIR/steghide.bin"
    else
      say "Tanpa passphrase gagal. Jalankan 'steghide-brute' atau beri -p '<pass>'."
    fi
  fi
}

run_steghide_brute() {
  echo ""
  say "=== Steghide brute-force passphrase ==="
  need steghide || return 1
  if [[ -z "$WORDLIST" ]]; then
    read -rp "Wordlist path (enter = /usr/share/wordlists/rockyou.txt): " WORDLIST
    [[ -z "$WORDLIST" ]] && WORDLIST="/usr/share/wordlists/rockyou.txt"
  fi
  [[ -f "$WORDLIST" ]] || { err "Wordlist tidak ada: $WORDLIST"; return 1; }
  local total=0
  total=$(wc -l < "$WORDLIST")
  ok "Mencoba ${total} kata dari $WORDLIST ... (Ctrl-C untuk stop)"
  local line pass
  while IFS= read -r pass; do
    pass="${pass%$'\r'}"
    [[ -z "$pass" ]] && continue
    if steghide extract -sf "$IMAGE" -p "$pass" -xf "$OUTDIR/steghide.bin" >/dev/null 2>&1; then
      ok "PASS PHRASE DITEMUKAN: '$pass'"
      ok "File diekstrak: $OUTDIR/steghide.bin"
      return 0
    fi
    total=$((total-1))
    if (( total % 50 == 0 )); then
      say "... sisa $total kata (terakhir coba: $pass)"
    fi
  done < "$WORDLIST"
  err "Tidak ada passphrase yang cocok di wordlist."
}

# ------------------------ 6) LSB / BITPLANE -------------------------------

run_lsb() {
  echo ""
  say "=== LSB analysis (numpy/PIL) ==="
  [[ -f "$PY" ]] || PY=python3
  if ! python3 -c "import numpy,PIL" 2>/dev/null; then
    err "Butuh numpy + Pillow: pip install numpy pillow"
    return 1
  fi
  python3 - "$IMAGE" <<'PY'
import sys
import numpy as np
from PIL import Image
img = Image.open(sys.argv[1])
img = img.convert("RGBA")
a = np.array(img)
print("Ukuran:", img.size, "Mode:", img.mode)
for name, idx in {"R":0,"G":1,"B":2,"A":3}.items():
    plane = (a[:,:,idx] & 1).astype(np.uint8)
    ones = int(plane.sum())
    total = plane.size
    print(f"  Channel {name}: LSB 1-bits = {ones}/{total} ({100*ones/total:.2f}%)")
PY
  say "Mengekstrak stream LSB tiap channel -> $OUTDIR/"
  python3 - "$IMAGE" "$OUTDIR/bitplane" <<'PY'
import sys
import numpy as np
from PIL import Image
img_path, outbase = sys.argv[1], sys.argv[2]
img = Image.open(img_path).convert("RGBA")
a = np.array(img)
for name, idx in {"R":0,"G":1,"B":2,"A":3}.items():
    plane = (a[:,:,idx] & 1).astype(np.uint8)
    flat = plane.flatten()
    pad = (8 - flat.size % 8) % 8
    bits = np.packbits(np.pad(flat, (0, pad)))
    bits.tofile(f"{outbase}_{name}_lsb.bin")
print("LSB streams saved")
PY
  echo ""
  say "=== Mencari string di tiap stream LSB ==="
  for ch in R G B A; do
    local f="$OUTDIR/bitplane_${ch}_lsb.bin"
    [[ -f "$f" ]] || continue
    local found
    found=$(strings -n 5 "$f" 2>/dev/null | head -3)
    if [[ -n "$found" ]]; then
      ok "[$ch] String ditemukan:"; echo "$found"
    fi
  done
  ok "File LSB stream: $OUTDIR/bitplane_*_lsb.bin"
}

run_lsb_msb() {
  echo ""
  say "=== LSB & MSB per channel + semua bit ==="
  python3 - "$IMAGE" "$OUTDIR/bitplane" <<'PY'
import sys
import numpy as np
from PIL import Image
img_path, outbase = sys.argv[1], sys.argv[2]
img = Image.open(img_path).convert("RGBA")
a = np.array(img)
def packbitsplane(plane):
    flat = plane.flatten()
    pad = (8 - flat.size % 8) % 8
    return np.packbits(np.pad(flat, (0, pad)))
for name, idx in {"R":0,"G":1,"B":2,"A":3}.items():
    for b in (0,1,7):  # LSB(0), bit1, MSB(7)
        plane = ((a[:,:,idx] >> b) & 1).astype(np.uint8)
        bits = packbitsplane(plane)
        bits.tofile(f"{outbase}_{name}_bit{b}.bin")
        # tampilkan string pendek pertama
print("done")
PY
  for ch in R G B A; do
    for b in 0 1 7; do
      local f="$OUTDIR/bitplane_${ch}_bit${b}.bin"
      [[ -f "$f" ]] || continue
      local found
      found=$(strings -n 5 "$f" 2>/dev/null | head -2)
      if [[ -n "$found" ]]; then
        ok "[$ch bit$b] String:"; echo "  $found"
      fi
    done
  done
  ok "Dump bitplane: $OUTDIR/bitplane_*"
}

run_bitplane_visual() {
  echo ""
  say "=== Visualisasi bitplane (simpan PNG per bit per channel) ==="
  python3 - "$IMAGE" "$OUTDIR/bitplane" <<'PY'
import sys
import numpy as np
from PIL import Image
img_path, outbase = sys.argv[1], sys.argv[2]
img = Image.open(img_path).convert("RGBA")
a = np.array(img)
for name, idx in {"R":0,"G":1,"B":2,"A":3}.items():
    for b in range(8):
        plane = (((a[:,:,idx] >> b) & 1) * 255).astype(np.uint8)
        Image.fromarray(plane, mode="L").save(f"{outbase}_{name}_bit{b}.png")
print("semua bitplane disimpan")
PY
  ok "Gambar bitplane tersimpan di $OUTDIR/ (nama: bitplane_*_R_bit0.png dst)"
  warn "Lihat pola di bit LSB (bit0/1) - pola tersembunyi tampil di sana."
}

# ------------------------ 7) ZSTEG -----------------------------------------

run_zsteg() {
  clear
  echo ""
  say "=== zsteg all-methods ==="
  need zsteg || return 1
  zsteg --all "$IMAGE" 2>&1
}

# ------------------------ 8) JPEG DCT ANALYSIS -----------------------------

run_jpeg() {
  echo ""
  if ! is_jpeg; then
    warn "File bukan JPEG. Analisa DCT khusus JPEG dilewati."
    return 0
  fi
  say "=== JPEG DCT / segment analysis ==="
  say "Struktur segment JPEG (SOI, APP, DQT, DHT, SOS, EOI):"
  python3 - "$IMAGE" <<'PY'
import sys, struct
data = open(sys.argv[1],'rb').read()
i = 2  # skip SOI
markers = {0xD8:'SOI',0xD9:'EOI',0xE0:'APP0(JFIF)',0xE1:'APP1(EXIF/XMP)',0xE2:'APP2(ICC)',0xDB:'DQT',0xC0:'SOF0',0xC4:'DHT',0xDA:'SOS',0xC2:'SOF2',0xFE:'COM',0xDD:'DRI'}
while i < len(data):
    if data[i] != 0xFF:
        i += 1; continue
    code = data[i+1]
    i += 2
    if code == 0xD8 or code == 0xD9:
        print(f"  offset {i-2:02X}: {markers.get(code,hex(code))}")
        if code == 0xD9: break
        continue
    # segment: 2-byte length after marker
    if i+1 >= len(data): break
    seglen = struct.unpack('>H', data[i:i+2])[0]
    name = markers.get(code, hex(code))
    print(f"  offset {i-2:02X}: {name} (len={seglen})")
    i += seglen
PY
  echo ""
  say "Cek data setelah EOI (append/stegano JPEG):"
  python3 - "$IMAGE" <<'PY'
import sys
data = open(sys.argv[1],'rb').read()
eoi = data.rfind(b'\xff\xd9')
if eoi == -1:
    print("  EOI tidak ditemukan - file mungkin terpotong/rusak")
else:
    tail = len(data) - (eoi + 2)
    print(f"  EOI di offset {eoi}; data setelah EOI: {tail} byte")
    if tail > 0:
        print("  >> ADA data tambahan setelah JPEG! Cek dengan strings/carve.")
        print(data[eoi+2:eoi+2+min(tail,128)])
    else:
        print("  Tidak ada data setelah EOI (file bersih).")
PY
}

# ------------------------ 9) EKSTRAKSI / CARVE ----------------------------

run_carve() {
  echo ""
  say "=== Carve / ekstrak embedded file (binwalk) ==="
  need binwalk || return 1
  local out="$OUTDIR/carve"
  mkdir -p "$out"
  say "Mengekstrak dengan binwalk -e ke $out ..."
  binwalk -e -C "$out" "$IMAGE" 2>&1 | tail -20
  echo ""
  if compgen -G "$out/*" > /dev/null; then
    ok "File hasil ekstraksi:"
    find "$out" -type f -exec ls -lh {} \; | awk '{print "  "$5"  "$9}'
  else
    warn "Tidak ada file diekstrak binwalk."
  fi
}

run_dd_extract() {
  echo ""
  say "=== Manual extract via dd (offset ke file) ==="
  local off
  off="${DD_OFFSET:-}"
  if [[ -z "$off" ]]; then
    read -rp "Offset byte (decimal, dari binwalk): " off
  fi
  [[ "$off" =~ ^[0-9]+$ ]] || { err "Offset tidak valid."; return 1; }
  local read_size="${DD_SIZE:-}"
  if [[ -z "$read_size" ]]; then
    read -rp "Panjang (byte, 0 = sampai akhir): " read_size
  fi
  local out="$OUTDIR/dd_${off}.bin"
  if [[ "$read_size" =~ ^[0-9]+$ && "$read_size" -gt 0 ]]; then
    dd if="$IMAGE" of="$out" bs=1 skip="$off" count="$read_size" 2>/dev/null
  else
    dd if="$IMAGE" of="$out" bs=1 skip="$off" 2>/dev/null
  fi
  if file "$out" | grep -qiE 'text|not stripped|ASCII|data'; then
    ok "Hasil: $out"
    file "$out"
  else
    warn "Output: $out"
    file "$out"
  fi
}

# ------------------------ 10) FULL AUTO ------------------------------------

run_full() {
  echo ""
  warn "=========== FULL SCAN ==========="
  run_info
  separator
  run_exif
  separator
  run_strings
  separator
  run_binwalk
  separator
  run_steghide
  separator
  run_lsb
  separator
  run_zsteg
  separator
  run_jpeg
  echo ""
  ok "=========== SELESAI. Hasil di: $OUTDIR ==========="
}

# ------------------------------ DISPATCH -----------------------------------

do_dispatch() {
  case "$METHOD" in
    info)     run_info;;
    exif)     run_exif;;
    strings)  run_strings;;
    binwalk)  run_binwalk;;
    steghide) run_steghide;;
    steghide-brute) run_steghide_brute;;
    lsb)      run_lsb;;
    lsb-msb)  run_lsb_msb;;
    bitplane) run_bitplane_visual;;
    zsteg)    run_zsteg;;
    jpeg)     run_jpeg;;
    carve)    run_carve;;
    dd)       run_dd_extract;;
    full)     run_full;;
    *) warn "METHOD tidak dikenal: $METHOD"; usage;;
  esac
}

is_method() {
  local m
  for m in info exif strings binwalk steghide steghide-brute lsb lsb-msb \
           bitplane zsteg jpeg carve dd full auto; do
    [[ "$1" == "$m" ]] && return 0
  done
  return 1
}

# ------------------------------ INTERAKTIF --------------------------------

pick_image() {
  if [[ -n "$IMAGE" ]]; then
    ok "Menggunakan gambar: $IMAGE"
    ensure_outdir
    return
  fi
  echo ""
  warn "Tidak ada file disediakan. Pencarian gambar (png/jpg/jpeg/bmp) di direktori ini & subdirektori..."
  mapfile -t CANDIDATES < <(find "$(pwd)" -maxdepth 3 -type f \( -iname '*.png' -o -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.bmp' -o -iname '*.gif' -o -iname '*.webp' \) 2>/dev/null)
  if [[ ${#CANDIDATES[@]} -eq 0 ]]; then
    err "Tidak ada gambar ditemukan. Beri path file sebagai argumen: $0 /path/img.png"
    exit 1
  fi
  echo "Gambar ditemukan:"
  local i
  for i in "${!CANDIDATES[@]}"; do
    printf "  [%d] %s\n" "$((i+1))" "${CANDIDATES[$i]}"
  done
  echo ""
  read -rp "Pilih nomor [1-${#CANDIDATES[@]}]: " sel
  if [[ ! "$sel" =~ ^[0-9]+$ || "$sel" -lt 1 || "$sel" -gt ${#CANDIDATES[@]} ]]; then
    err "Pilihan tidak valid."; exit 1
  fi
  IMAGE="${CANDIDATES[$((sel-1))]}"
  ok "Menggunakan: $IMAGE"
  ensure_outdir
}

main_menu() {
  local m
  while true; do
    echo ""
    echo "======================================================================"
    echo -e "  ${STYLE}Image Steganography & Forensics Toolkit${RESET}"
    echo "======================================================================"
    echo -e "  File   : ${GRN}${IMAGE}${RESET}  (${BLU}$(file_format)${RESET})"
    echo -e "  Outdir : ${BLU}${OUTDIR}${RESET}"
    echo "----------------------------------------------------------------------"
    echo "  1) Info dasar             2) Metadata EXIF"
    echo "  3) String scan            4) Binwalk (embedded file)"
    echo "  5) Steghide extract       6) Steghide brute-force"
    echo "  7) LSB extraction         8) LSB+MSB / semua bit"
    echo "  9) Visual bitplane PNG   10) zsteg all-methods"
    echo " 11) JPEG DCT analysis     12) Carve file (binwalk -e)"
    echo " 13) dd manual extract     14) FULL SCAN (semua)"
    echo "----------------------------------------------------------------------"
    echo -e "  P) Set passphrase steghide   W) Set wordlist"
    echo -e "  F) Ganti file                L) Lihat output dir   Q) Keluar"
    echo "----------------------------------------------------------------------"
    read -rp "Pilih menu: " m
    case "$m" in
      1) METHOD=info; do_dispatch;;
      2) METHOD=exif; do_dispatch;;
      3) METHOD=strings; do_dispatch;;
      4) METHOD=binwalk; do_dispatch;;
      5) METHOD=steghide; do_dispatch;;
      6) METHOD=steghide-brute; do_dispatch;;
      7) METHOD=lsb; do_dispatch;;
      8) METHOD=lsb-msb; do_dispatch;;
      9) METHOD=bitplane; do_dispatch;;
     10) METHOD=zsteg; do_dispatch;;
     11) METHOD=jpeg; do_dispatch;;
     12) METHOD=carve; do_dispatch;;
     13) METHOD=dd; do_dispatch;;
     14) METHOD=full; do_dispatch;;
      [pP]) read -rsp "  Passphrase steghide: " PASSPHRASE; echo ""; ok "Passphrase diset.";;
      [wW]) read -rp "  Wordlist: " WORDLIST; ok "Wordlist: $WORDLIST";;
      [fF]) IMAGE=""; pick_image;;
      [lL]) ls -lh "$OUTDIR";;
      [qQ]) exit 0;;
      *) warn "Pilihan tidak dikenal: $m";;
    esac
  done
}

# ------------------------------- USAGE -------------------------------------

usage() {
  echo ""
  echo "Image Steganography & Forensics Toolkit (PNG/JPG)"
  echo "=================================================="
  echo "  $0                                   -> menu interaktif"
  echo "  $0 /path/img.png                     -> pilih file, lalu menu"
  echo "  $0 /path/img.png <method>            -> langsung scan"
  echo "  $0 -p '<pass>'  /path/img.png steghide"
  echo "  $0 -w wordlist.txt /path/img.png steghide-brute"
  echo "  $0 -o <offset> -s <size> /path/img.png dd"
  echo ""
  echo "Method:"
  echo "  info        - info dasar file & identify"
  echo "  exif        - metadata EXIF + flag menarik"
  echo "  strings     - ekstraksi string + pola flag + cek trailing data"
  echo "  binwalk     - scan embedded file signature"
  echo "  steghide    - extract data (pakai -p untuk passphrase)"
  echo "  steghide-brute - brute passphrase dgn wordlist (-w)"
  echo "  lsb         - ekstrak stream LSB tiap channel + cari string"
  echo "  lsb-msb     - ekstrak bit 0/1/7 tiap channel"
  echo "  bitplane    - simpan visualisasi ke-8 bit tiap channel ke PNG"
  echo "  zsteg       - semua metode zsteg (PNG/BMP)"
  echo "  jpeg        - analisa segment/struktur JPEG + trailing"
  echo "  carve       - ekstrak embedded file (-e)"
  echo "  dd          - extract manual by offset (-o offset [-s size])"
  echo "  full        - jalankan SEMUA metode"
  echo "  auto        - alias full"
  echo ""
  echo "Env var: STEG_STRING_PAT  = regex pola string tambahan"
  echo ""
  echo "Requirement (opsional per modul): exiftool binwalk steghide zsteg"
  echo "  identify (imagemagick) python3+numpy+Pillow (utk LSB/bitplane)"
}

# ------------------------------- MAIN --------------------------------------

PY="$(command -v python3 || echo python3)"

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p) PASSPHRASE="${2:-}"; shift 2;;
      -w) WORDLIST="${2:-}"; shift 2;;
      -o) DD_OFFSET="${2:-}"; shift 2;;
      -s) DD_SIZE="${2:-}"; shift 2;;
      -h|--help) usage; exit 0;;
      *) break;;
    esac
  done

  # arg pertama = file gambar
  if [[ $# -ge 1 ]]; then
    IMAGE="$(resolve "$1")"
    shift
    [[ -f "$IMAGE" ]] || { err "File tidak ditemukan: $IMAGE"; usage; exit 1; }
    ensure_outdir
  fi

  # sisa arg = method
  if [[ $# -ge 1 ]]; then
    METHOD="$1"
    if is_method "$METHOD"; then
      if [[ "$METHOD" == "auto" ]]; then METHOD=full; fi
      do_dispatch
      exit 0
    else
      err "Method tidak dikenal: $METHOD"; usage; exit 1
    fi
  fi

  # tidak ada method -> interaktif
  pick_image
  main_menu
}

main "$@"
