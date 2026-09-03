#!/usr/bin/env bash
# =============================================================================
#  Universal Strings & Regex Toolkit
#  --------------------------------------------------------------------------
#  Tool serbaguna untuk mencari string/regex di SEMUA jenis file:
#  file teks biasa, binary, executable, disk image (.img/.dd/.raw),
#  virtual disk (vmdk/vdi/vhd/qcow2), arsip (zip/7z/gz/tar),
#  dokumen (pdf/docx), gambar, pcap, dan tipe file apapun.
#
#  Menggabungkan kekuatan: strings + grep + regex + binwalk + python
#  untuk ekstraksi dan pencarian menyeluruh.
#
#  Fitur:
#   [STR]   - Ekstrak semua printable strings dari file (semua tipe)
#   [REGEX] - Cari string dengan regex di semua file (rekursif)
#   [FLAG]  - Auto-hunt flag/secret/password pattern (CTF-ready)
#   [FILE]  - List semua file di direktori dengan info tipe
#   [HEX]   - Cari pola di hex dump (offset + hex + ASCII)
#   [NEST]  - Ekstrak file tersembunyi/embedded dari binary (binwalk)
#   [MULTI] - Batch search: cari banyak pola sekaligus
#   [ENCODE]- Deteksi & dekode string ter-encode (base64/hex/rot di dalam binary)
#   [STAT]  - Statistik: entropi, distribusi byte, file info
#
#  Cara pakai:
#     ./strings_tool.sh                              -> menu interaktif
#     ./strings_tool.sh <file>                       -> strings cepat (semua tipe)
#     ./strings_tool.sh str <file> [minlen]          -> extract strings
#     ./strings_tool.sh regex <file> <pattern>       -> regex search
#     ./strings_tool.sh flag <file>                  -> hunt flag/secret
#     ./strings_tool.sh scan <folder> <pattern>      -> recursive search
#     ./strings_tool.sh hex <file> <hex-pattern>     -> cari hex di binary
#     ./strings_tool.sh nest <file>                  -> extract embedded files
#     ./strings_tool.sh multi <file> <pola1,pola2>   -> cari banyak pola
#     ./strings_tool.sh encode <file>                -> deteksi string ter-encode
#     ./strings_tool.sh stat <file>                  -> info & entropi
#     ./strings_tool.sh deep <file> <pattern>        -> deep search: strings + grep + regex
#     ./strings_tool.sh disk <disk-image> <pattern>  -> search di disk image
#
#  Requirement: file, strings, grep, xxd, python3
#  (opsional: binwalk, 7z, nmap --script)
#
#  FLAG PREFIX (opsional):
#     ./strings_tool.sh --prefix "KTCG,CTF,MyCTF,{}" <file>
#     export FLAGPREFIX="KTCG,CTF,{}"
#     Default: KTCG,flag,FLAG,ctf,CTF,secret,{}
# =============================================================================

set -uo pipefail

# ----------------------------- KONFIGURASI --------------------------------
PY="python3"
STRINGS="strings"
GREP="grep"
XXD="xxd"
FILE_CMD="file"
STYLE="\e[1;36m"; RESET="\e[0m"
RED="\e[1;31m"; GRN="\e[1;32m"; YLW="\e[1;33m"; BLU="\e[1;34m"; MGT="\e[1;35m"; ORG="\e[1;33m"

TARGET=""
FOLDER=""
MINLEN=4
OUTDIR_BASE="$(pwd)/strings_result"

# --- Flag prefix ---
load_flag_prefix() {
  local conf=".strings_tool.conf"
  if [[ -n "${CLI_PREFIX:-}" ]]; then
    FLAGPREFIX="$CLI_PREFIX"
  elif [[ -n "${FLAGPREFIX:-}" ]]; then
    :
  elif [[ -f "$conf" ]]; then
    local val
    val=$(grep -E '^FLAGPREFIX=' "$conf" 2>/dev/null | head -1 | cut -d= -f2-)
    FLAGPREFIX="${val:-KTCG,flag,FLAG,ctf,CTF,secret,{}"
  else
    FLAGPREFIX="KTCG,flag,FLAG,ctf,CTF,secret,{}"
  fi
  build_flag_regex
}

build_flag_regex() {
  local IFS=','
  local out=""
  for p in $FLAGPREFIX; do
    [[ -z "$p" ]] && continue
    local esc="${p//\//\\/}"
    esc=$(printf '%s' "$esc" | sed -e 's/[.[\*^$()+?{|]/\\&/g')
    out="$out${out:+|}$esc"
  done
  [[ -z "$out" ]] && out="KTCG|flag|FLAG|ctf|CTF|secret"
  FLAGREGEX="$out"
}

flag_matches() {
  printf '%s\n' "$1" | grep -qaiE "$FLAGREGEX"
}

flaghl() {
  local line
  while IFS= read -r line; do
    if printf '%s\n' "$line" | grep -qaiE "$FLAGREGEX"; then
      echo -e "  ${GRN}[F]${RESET} $line"
    else
      echo "     $line"
    fi
  done
}

# ----------------------------- UTILITAS -----------------------------------
say()  { echo -e "${STYLE}[*]${RESET} $*"; }
ok()   { echo -e "${GRN}[+]${RESET} $*"; }
warn() { echo -e "${YLW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[-]${RESET} $*"; }
info() { echo -e "${BLU}[i]${RESET} $*"; }
sub()  { echo -e "     $*"; }

has() { command -v "$1" >/dev/null 2>&1; }

resolve() {
  local p="$1"
  if [[ "$p" != /* ]]; then p="$(pwd)/$p"; fi
  echo "$p"
}

slug() { basename "$1" | sed -E 's/[^A-Za-z0-9._-]+/_/g'; }

ensure_outdir() {
  mkdir -p "$OUTDIR_BASE" 2>/dev/null
}

# Deteksi tipe file untuk menentukan strategi pencarian
detect_file_type() {
  local f="$1"
  local sig ext
  sig=$(file -b "$f" 2>/dev/null)
  ext="${f##*.}"; ext="${ext,,}"

  case "$sig" in
    *"ASCII text"*|*"UTF-8 Unicode text"*|*"ISO-8859"*|*"empty"*)
      echo "text"; return;;
    *"ELF"*|*"PE32"*|*"Mach-O"*|*"executable"*)
      echo "binary"; return;;
    *"gzip compressed"*|*"Zip archive"*|*"tar archive"*|*"bzip2"*|*"7-zip"*|*"XZ"*|*"AR archive"*)
      echo "archive"; return;;
    *"QEMU QCOW"*) echo "qcow2"; return;;
    *"VirtualBox Disk"*|*"VDI"*) echo "vdi"; return;;
    *"VMware"*|*"VMDK"*) echo "vmdk"; return;;
    *"Virtual Hard Disk"*|*"VHD"*) echo "vhd"; return;;
    *"E01"*|*"EnCase"*|*"EWF"*) echo "ewf"; return;;
    *"ISO 9660"*|*"isofs"*|*"UDF"*) echo "iso"; return;;
    *"DOS/MBR"*|*"x86 boot"*|*"GPT"*|*"ext2"*|*"ext3"*|*"ext4"*|*"Linux rev"*)
      echo "raw-disk"; return;;
    *"PCAP"*|*"tcpdump"*) echo "pcap"; return;;
    *"PNG image"*) echo "png"; return;;
    *"JPEG"*|*"JFIF"*) echo "jpeg"; return;;
    *"PDF"*|*"PDF document"*) echo "pdf"; return;;
    *"Microsoft Word"*|*"Microsoft Excel"*|*"Composite Document"*)
      echo "msoffice"; return;;
    *"SQLite"*|*"database"*) echo "database"; return;;
    *"XML"*) echo "xml"; return;;
    *"JSON"*) echo "json"; return;;
  esac
  # fallback ekstensi
  case "$ext" in
    txt|log|csv|md|py|sh|bash|js|ts|go|rs|c|h|java|rb|php|pl|lua|r) echo "text";;
    png|jpg|jpeg|gif|bmp|svg|webp|ico|tiff) echo "image";;
    mp3|mp4|avi|mkv|flac|wav|ogg) echo "media";;
    pcap|pcapng|cap) echo "pcap";;
    pdf) echo "pdf";;
    zip|7z|gz|bz2|xz|tar|rar|apk|jar|war) echo "archive";;
    img|dd|raw|bin|iso) echo "raw-disk";;
    e01|e02|ewf) echo "ewf";;
    vmdk) echo "vmdk";;
    vdi) echo "vdi";;
    vhd) echo "vhd";;
    qcow2) echo "qcow2";;
    db|sqlite|sqlite3) echo "database";;
    *) echo "unknown";;
  esac
}

# Hitung entropi byte (0-8)
calc_entropy() {
  "$PY" -c "
import sys, collections, math
data = open(sys.argv[1], 'rb').read()
if not data:
    print(0.0); sys.exit(0)
c = collections.Counter(data)
n = len(data)
ent = -sum((v/n) * math.log2(v/n) for v in c.values())
print(f'{ent:.3f}')
" "$1" 2>/dev/null
}

# Print hexdump dengan warna
color_hexdump() {
  "$PY" -c "
import sys
data = sys.stdin.buffer.read()
RED='\033[1;31m'; GRN='\033[1;32m'; YLW='\033[1;33m'; RST='\033[0m'
for i in range(0, min(len(data), 4096), 16):
    chunk = data[i:i+16]
    hex_part = ''
    ascii_part = ''
    for j, b in enumerate(chunk):
        h = f'{b:02x}'
        c = chr(b) if 32 <= b < 127 else '.'
        if b == 0:
            hex_part += f'{YLW}{h}{RST} '
        elif 32 <= b < 127:
            hex_part += f'{GRN}{h}{RST} '
        else:
            hex_part += f'{RED}{h}{RST} '
        ascii_part += f'{GRN}{c}{RST}' if 32 <= b < 127 else f'{RED}.{RST}'
    print(f'  {i:08x}  {hex_part:<49} {ascii_part}')
" 2>/dev/null
}

# ------------------------------- STRINGS -----------------------------------
cmd_str() {
  local file="$1" min="${2:-$MINLEN}"
  [[ -f "$file" ]] || { err "File tidak ditemukan: $file"; return 1; }

  local ftype
  ftype=$(detect_file_type "$file")
  local sz
  sz=$(stat -c%s "$file" 2>/dev/null || echo 0)

  echo ""
  say "Extract strings: $file"
  info "Tipe: ${MGT}$ftype${RESET} | Ukuran: ${BLU}$(numfmt --to=iec $sz 2>/dev/null || echo "${sz}B")${RESET} | Min length: $min"

  case "$ftype" in
    text)
      info "File teks - menampilkan semua baris non-kosong:"
      grep -n '.' "$file" 2>/dev/null | head -500
      ;;
    archive|qcow2|vdi|vhd|vmdk|ewf|iso|raw-disk|pcap)
      warn "File tipe khusus ($ftype) - ekstrak strings dari raw bytes:"
      "$STRINGS" -n "$min" "$file" 2>/dev/null | head -500
      info "Gunakan 'nest' untuk extract file embedded, atau 'disk' untuk mount+search"
      ;;
    image|media)
      warn "File media ($ftype) - extract strings dari binary:"
      "$STRINGS" -n "$min" "$file" 2>/dev/null | head -200
      info "File media jarang punya string bermakna kecuali metadata"
      ;;
    *)
      "$STRINGS" -n "$min" "$file" 2>/dev/null | head -500
      ;;
  esac
}

# ------------------------------- REGEX SEARCH -----------------------------
cmd_regex() {
  local file="$1" pattern="$2"
  [[ -f "$file" ]] || { err "File tidak ditemukan: $file"; return 1; }
  [[ -z "$pattern" ]] && { err "Pattern kosong"; return 1; }

  local ftype
  ftype=$(detect_file_type "$file")

  echo ""
  say "Regex search: '$pattern' di $file"
  info "Tipe: ${MGT}$ftype${RESET}"

  case "$ftype" in
    text)
      info "File teks - grep langsung:"
      grep -naiE "$pattern" "$file" 2>/dev/null | head -200 | flaghl
      ;;
    binary|pcap|image|media)
      warn "File binary - ekstrak strings dulu lalu regex:"
      "$STRINGS" -n "$MINLEN" "$file" 2>/dev/null | grep -naiE "$pattern" 2>/dev/null | head -200 | flaghl
      ;;
    archive|qcow2|vdi|vhd|vmdk|ewf|iso|raw-disk)
      warn "File tipe khusus - search di raw bytes:"
      "$STRINGS" -n "$MINLEN" "$file" 2>/dev/null | grep -naiE "$pattern" 2>/dev/null | head -200 | flaghl
      info "Gunakan 'disk' untuk search lebih dalam (mount + recursive)"
      ;;
    *)
      "$STRINGS" -n "$MINLEN" "$file" 2>/dev/null | grep -naiE "$pattern" 2>/dev/null | head -200 | flaghl
      ;;
  esac
}

# ------------------------------- FLAG HUNT ---------------------------------
cmd_flag() {
  local file="$1"
  [[ -f "$file" ]] || { err "File tidak ditemukan: $file"; return 1; }

  echo ""
  say "Flag/secret hunt: $file (prefix: $FLAGPREFIX)"

  # 1. Strings langsung
  echo -e "${STYLE}== Strings dengan pola flag ==${RESET}"
  local found
  found=$("$STRINGS" -n 4 "$file" 2>/dev/null | grep -aiE "$FLAGREGEX|\{[^}]{3,}\}" | head -30)
  if [[ -n "$found" ]]; then
    ok "Ditemukan:"
    printf '%s\n' "$found" | flaghl | sed 's/^/    /'
  else
    warn "Tidak ada match langsung di strings"
  fi

  # 2. Base64 candidates -> decode
  echo ""
  echo -e "${STYLE}== Kandidat ter-encode (base64/hex) yang mungkin flag ==${RESET}"
  "$STRINGS" -n 8 "$file" 2>/dev/null | python3 -c "
import sys, re, base64
for line in sys.stdin:
    s = line.strip()
    if not s or len(s) < 8: continue
    # cek brace flag langsung
    if re.search(r'\{[^}]{2,}\}', s):
        print(f'  [PLAIN] {s}')
        continue
    # cek base64
    clean = re.sub(r'[^A-Za-z0-9+/=]', '', s)
    if len(clean) >= 12 and re.fullmatch(r'[A-Za-z0-9+/=]+', clean):
        try:
            dec = base64.b64decode(clean + '==' * (-len(clean) % 4)).decode('latin-1')
            if re.search(r'[A-Za-z]{3,}', dec) and len(dec) >= 4:
                print(f'  [B64]   {s} -> {dec}')
        except: pass
    # cek hex
    h = re.sub(r'[^0-9a-fA-F]', '', s)
    if len(h) >= 16 and len(h) % 2 == 0:
        try:
            dec = bytes.fromhex(h).decode('latin-1')
            printable = sum(1 for c in dec if 32 <= ord(c) < 127)
            if printable >= len(dec) * 0.6 and len(dec) >= 4:
                print(f'  [HEX]   {s} -> {dec}')
        except: pass
" 2>/dev/null | head -20

  # 3. Object dump .rodata jika ELF
  local sig
  sig=$(file -b "$file" 2>/dev/null)
  if [[ "$sig" == *"ELF"* ]]; then
    echo ""
    echo -e "${STYLE}== ELF .rodata flag search ==${RESET}"
    objdump -s -j .rodata "$file" 2>/dev/null | grep -aiE "$FLAGREGEX|\{" | flaghl | sed 's/^/    /' | head -20
  fi
}

# ------------------------------- FOLDER SCAN -------------------------------
cmd_scan() {
  local folder="$1" pattern="$2"
  [[ -d "$folder" ]] || { err "Folder tidak ditemukan: $folder"; return 1; }
  [[ -z "$pattern" ]] && { err "Pattern kosong"; return 1; }

  echo ""
  say "Recursive scan: '$pattern' di $folder"

  # 1. Grep teks
  echo -e "${STYLE}== File teks (grep -rn) ==${RESET}"
  grep -rnaiE "$pattern" "$folder" 2>/dev/null | head -100 | flaghl | sed 's/^/    /'

  # 2. Binary strings
  echo ""
  echo -e "${STYLE}== File binary (strings + regex) ==${RESET}"
  find "$folder" -type f 2>/dev/null | while read -r f; do
    local ftype
    ftype=$(detect_file_type "$f")
    case "$ftype" in
      text|json|xml|html) continue ;;  # sudah di-grep di atas
      *)
        local hits
        hits=$("$STRINGS" -n "$MINLEN" "$f" 2>/dev/null | grep -naiE "$pattern" 2>/dev/null)
        if [[ -n "$hits" ]]; then
          ok "$f:"
          printf '%s\n' "$hits" | head -5 | sed 's/^/      /'
        fi
        ;;
    esac
  done
}

# ------------------------------- HEX SEARCH -------------------------------
cmd_hex() {
  local file="$1" hexpat="$2"
  [[ -f "$file" ]] || { err "File tidak ditemukan: $file"; return 1; }
  [[ -z "$hexpat" ]] && { err "Hex pattern kosong"; return 1; }

  echo ""
  say "Hex search: '$hexpat' di $file"

  # Convert hex pattern (tolerate 0x prefix, spaces, colons)
  local clean
  clean=$(echo "$hexpat" | sed 's/0x//g; s/://g; s/ //g')
  if [[ ${#clean} -lt 2 || $(( ${#clean} % 2 )) -ne 0 ]]; then
    err "Hex pattern harus genap digit (contoh: '4b544347' atau '4b 54 43 47')"
    return 1
  fi

  "$PY" -c "
import sys, re
pattern = bytes.fromhex(sys.argv[1])
data = open(sys.argv[2], 'rb').read()
matches = []
for m in re.finditer(re.escape(pattern), data):
    off = m.start()
    ctx = data[max(0,off-16):off+len(pattern)+16]
    hex_ctx = ' '.join(f'{b:02x}' for b in ctx)
    ascii_ctx = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
    matches.append((off, hex_ctx, ascii_ctx))
if not matches:
    print('  (tidak ditemukan)')
else:
    print(f'  Ditemukan {len(matches)} match:')
    for off, hx, asc in matches[:50]:
        print(f'  0x{off:08x}  {hx}')
        print(f'            {asc}')
" "$clean" "$file" 2>/dev/null
}

# ------------------------------- NESTED EXTRACT ----------------------------
cmd_nest() {
  local file="$1"
  [[ -f "$file" ]] || { err "File tidak ditemukan: $file"; return 1; }

  echo ""
  say "Extract embedded/nested files: $file"
  ensure_outdir
  local destdir="$OUTDIR_BASE/$(slug "$file")_nested"
  mkdir -p "$destdir"

  if has binwalk; then
    info "Menggunakan binwalk untuk extract..."
    binwalk -M -e -C "$destdir" "$file" 2>/dev/null
    local n
    n=$(find "$destdir" -type f 2>/dev/null | wc -l)
    ok "Extracted $n file ke $destdir"
    # tampilkan beberapa file
    find "$destdir" -type f 2>/dev/null | head -20 | while read -r f; do
      local sz ftype
      sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
      ftype=$(detect_file_type "$f")
      echo "    $f  ($ftype, ${sz}B)"
    done
  elif has 7z; then
    info "Binwalk tidak ada - coba 7z extract..."
    7z x -o"$destdir" -y "$file" >/dev/null 2>&1
    ok "Extract ke $destdir"
  else
    err "Binwalk dan 7z tidak terpasang. Install: apt install binwalk p7zip-full"
    return 1
  fi
}

# ------------------------------- MULTI PATTERN -----------------------------
cmd_multi() {
  local file="$1" patterns="$2"
  [[ -f "$file" ]] || { err "File tidak ditemukan: $file"; return 1; }
  [[ -z "$patterns" ]] && { err "Pattern kosong (pisah koma)"; return 1; }

  echo ""
  say "Multi-pattern search: $file"

  local IFS=','
  local idx=0
  for pat in $patterns; do
    [[ -z "$pat" ]] && continue
    idx=$((idx+1))
    echo -e "${STYLE}== [$idx] Pattern: '$pat' ==${RESET}"
    local hits
    hits=$("$STRINGS" -n "$MINLEN" "$file" 2>/dev/null | grep -naiE "$pat" 2>/dev/null | head -10)
    if [[ -n "$hits" ]]; then
      ok "Match:"
      printf '%s\n' "$hits" | flaghl | sed 's/^/    /'
    else
      warn "Tidak ada match untuk '$pat'"
    fi
    echo ""
  done
}

# ------------------------------- ENCODE DETECT -----------------------------
cmd_encode() {
  local file="$1"
  [[ -f "$file" ]] || { err "File tidak ditemukan: $file"; return 1; }

  echo ""
  say "Deteksi & dekode string ter-encode: $file"

  "$STRINGS" -n 8 "$file" 2>/dev/null | "$PY" -c "
import sys, re, base64, binascii

results = {'base64': [], 'hex': [], 'url': [], 'rot13': [], 'jwt': [], 'uri': []}

def is_printable(s, threshold=0.6):
    if not s: return False
    good = sum(1 for c in s if 32 <= ord(c) < 127 or c in '\n\r\t')
    return good / len(s) >= threshold

for line in sys.stdin:
    s = line.strip()
    if not s or len(s) < 6: continue

    # Base64
    clean = re.sub(r'[^A-Za-z0-9+/=]', '', s)
    if len(clean) >= 12 and re.fullmatch(r'[A-Za-z0-9+/=]+', clean):
        try:
            dec = base64.b64decode(clean + '==' * (-len(clean) % 4)).decode('latin-1')
            if is_printable(dec, 0.7) and len(dec) >= 4:
                results['base64'].append((s[:80], dec[:120]))
        except: pass

    # Hex string
    h = re.sub(r'[^0-9a-fA-F]', '', s)
    if len(h) >= 16 and len(h) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in h[:32]):
        try:
            dec = bytes.fromhex(h).decode('latin-1')
            if is_printable(dec, 0.6) and len(dec) >= 4:
                results['hex'].append((s[:80], dec[:120]))
        except: pass

    # URL encoded
    if '%' in s and re.search(r'%[0-9a-fA-F]{2}', s):
        try:
            from urllib.parse import unquote
            dec = unquote(s)
            if dec != s and is_printable(dec, 0.7):
                results['url'].append((s[:80], dec[:120]))
        except: pass

    # JWT
    if re.match(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', s):
        results['jwt'].append((s[:120], '(JWT token)'))

    # ROT13
    rot = s.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
    if rot != s and is_printable(rot, 0.7) and re.search(r'[a-z]{4,}', rot):
        results['rot13'].append((s[:80], rot[:120]))

# Output
total = sum(len(v) for v in results.values())
if total == 0:
    print('  (tidak ada string ter-encode yang terdeteksi)')
else:
    for enc_type, items in results.items():
        if items:
            print(f'\n  [{enc_type.upper()}] ({len(items)} kandidat):')
            for orig, decoded in items[:5]:
                print(f'    {orig}')
                print(f'      -> {decoded}')
print(f'\n  Total kandidat: {total}')
" 2>/dev/null
}

# ------------------------------- STATISTICS --------------------------------
cmd_stat() {
  local file="$1"
  [[ -f "$file" ]] || { err "File tidak ditemukan: $file"; return 1; }

  echo ""
  say "Statistik file: $file"

  local sz ftype ent
  sz=$(stat -c%s "$file" 2>/dev/null || echo 0)
  ftype=$(detect_file_type "$file")

  echo -e "${STYLE}== Info ==${RESET}"
  echo "  File      : $file"
  echo "  Tipe      : $ftype"
  echo "  Ukuran    : $(numfmt --to=iec $sz 2>/dev/null || echo "${sz}B") ($sz bytes)"
  echo "  File cmd  : $(file -b "$file" 2>/dev/null)"

  echo ""
  echo -e "${STYLE}== Entropi ==${RESET}"
  ent=$(calc_entropy "$file")
  echo "  Entropi   : $ent / 8.0"
  local entbar
  entbar=$(python3 -c "e=float('$ent'); bar='#'*int(e*5); pad='-'*(40-int(e*5)); print(f'  [{bar}{pad}] {e:.2f}/8.00')" 2>/dev/null)
  echo "$entbar"
  if python3 -c "exit(0 if float('$ent') > 7.0 else 1)" 2>/dev/null; then
    warn "Entropi sangat tinggi -> kemungkinan terenkripsi/packed/compressed"
  elif python3 -c "exit(0 if float('$ent') > 5.5 else 1)" 2>/dev/null; then
    info "Entropi sedang -> mungkin compressed atau campuran data"
  else
    info "Entropi rendah -> data teks atau structured"
  fi

  echo ""
  echo -e "${STYLE}== Strings ==${RESET}"
  local strcount
  strcount=$("$STRINGS" -n "$MINLEN" "$file" 2>/dev/null | wc -l)
  echo "  String >= $MINLEN char : $strcount"
  echo "  String unik            : $("$STRINGS" -n "$MINLEN" "$file" 2>/dev/null | sort -u | wc -l)"

  echo ""
  echo -e "${STYLE}== Magic bytes ==${RESET}"
  xxd -l 32 "$file" 2>/dev/null | head -4 | sed 's/^/    /'
}

# ------------------------------- DEEP SEARCH -------------------------------
cmd_deep() {
  local file="$1" pattern="$2"
  [[ -f "$file" ]] || { err "File tidak ditemukan: $file"; return 1; }
  [[ -z "$pattern" ]] && { err "Pattern kosong"; return 1; }

  echo ""
  say "Deep search: '$pattern' di $file"

  # Method 1: grep langsung (untuk teks)
  echo -e "${STYLE}== [1] Direct grep ==${RESET}"
  local g1
  g1=$(grep -naiE "$pattern" "$file" 2>/dev/null | head -20)
  if [[ -n "$g1" ]]; then
    ok "Direct grep:"
    printf '%s\n' "$g1" | flaghl | sed 's/^/    /'
  else
    info "Tidak ada match langsung"
  fi

  # Method 2: strings lalu grep
  echo ""
  echo -e "${STYLE}== [2] Strings + grep ==${RESET}"
  local g2
  g2=$("$STRINGS" -n "$MINLEN" "$file" 2>/dev/null | grep -naiE "$pattern" 2>/dev/null | head -20)
  if [[ -n "$g2" ]]; then
    ok "Strings match:"
    printf '%s\n' "$g2" | flaghl | sed 's/^/    /'
  else
    info "Tidak ada match di strings"
  fi

  # Method 3: hex offset search
  echo ""
  echo -e "${STYLE}== [3] Hex offset ==${RESET}"
  "$PY" -c "
import sys, re
pattern = sys.argv[1]
try:
    data = open(sys.argv[2], 'rb').read()
    for m in re.finditer(pattern.encode(), data, re.IGNORECASE):
        off = m.start()
        ctx = data[max(0,off-8):off+len(m.group())+8]
        hx = ' '.join(f'{b:02x}' for b in ctx)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f'  0x{off:08x}  {hx}  |{asc}|')
except Exception as e:
    print(f'  (error: {e})')
" "$pattern" "$file" 2>/dev/null | head -20

  # Method 4: XOR bruteforce (single byte)
  echo ""
  echo -e "${STYLE}== [4] XOR bruteforce 1-byte ==${RESET}"
  "$PY" -c "
import sys, re
pat = sys.argv[1].lower()
data = open(sys.argv[2], 'rb').read()
if len(data) > 1000000:
    data = data[:1000000]  # limit
found = False
for k in range(256):
    dec = bytes(b ^ k for x, b in enumerate(data) if True for b in [data[x]])
    # gunakan slice langsung
    dec = bytes(b ^ k for b in data)
    text = dec.decode('latin-1', errors='replace')
    if re.search(pat, text, re.IGNORECASE):
        context = re.findall(r'.{0,30}' + pat + r'.{0,30}', text, re.IGNORECASE)
        for ctx in context[:2]:
            print(f'  key 0x{k:02x} (chr={chr(k) if 32<=k<127 else \".\"}): ...{ctx.strip()}...')
        found = True
if not found:
    print('  (tidak ditemukan via XOR 1-byte)')
" "$pattern" "$file" 2>/dev/null | head -10
}

# ------------------------------- DISK IMAGE SEARCH -------------------------
cmd_disk() {
  local image="$1" pattern="$2"
  [[ -f "$image" ]] || { err "File tidak ditemukan: $image"; return 1; }
  [[ -z "$pattern" ]] && { err "Pattern kosong"; return 1; }

  echo ""
  say "Disk image search: '$pattern' di $image"

  ensure_outdir
  local tmpdir="$OUTDIR_BASE/disk_tmp_$$"
  mkdir -p "$tmpdir"

  local ftype
  ftype=$(detect_file_type "$image")
  info "Tipe image: ${MGT}$ftype${RESET}"

  # Strategy: extract dulu, lalu search
  case "$ftype" in
    text)
      # file teks, langsung search
      grep -naiE "$pattern" "$image" 2>/dev/null | head -50 | flaghl | sed 's/^/    /'
      ;;
    raw-disk|qcow2|vdi|vhd|vmdk|ewf|iso)
      # coba mount dulu
      if [[ "$ftype" == "raw-disk" ]] && has sudo && sudo -n true 2>/dev/null; then
        info "Mencoba mount image (read-only)..."
        local mp="/mnt/str_$$"
        sudo mkdir -p "$mp" 2>/dev/null
        if sudo mount -o ro,loop "$image" "$mp" 2>/dev/null; then
          ok "Mounted ke $mp"
          info "Recursive search di mount point..."
          grep -rnaiE "$pattern" "$mp" 2>/dev/null | head -50 | flaghl | sed 's/^/    /'
          sudo umount "$mp" 2>/dev/null
          sudo rmdir "$mp" 2>/dev/null
        else
          warn "Mount gagal - fallback ke strings"
        fi
      fi
      # fallback: strings dari raw bytes
      info "Search di raw bytes (strings + regex)..."
      "$STRINGS" -n "$MINLEN" "$image" 2>/dev/null | grep -naiE "$pattern" 2>/dev/null | head -50 | flaghl | sed 's/^/    /'
      ;;
    archive)
      info "Extract archive dulu..."
      if has 7z; then
        7z x -o"$tmpdir" -y "$image" >/dev/null 2>&1
        info "Search di isi archive..."
        grep -rnaiE "$pattern" "$tmpdir" 2>/dev/null | head -50 | flaghl | sed 's/^/    /'
        # juga search strings binary
        find "$tmpdir" -type f 2>/dev/null | while read -r f; do
          local h
          h=$("$STRINGS" -n "$MINLEN" "$f" 2>/dev/null | grep -naiE "$pattern" 2>/dev/null)
          if [[ -n "$h" ]]; then
            ok "$f:"
            printf '%s\n' "$h" | head -5 | sed 's/^/      /'
          fi
        done
      fi
      ;;
    *)
      # generic: strings + grep
      "$STRINGS" -n "$MINLEN" "$image" 2>/dev/null | grep -naiE "$pattern" 2>/dev/null | head -50 | flaghl | sed 's/^/    /'
      ;;
  esac

  rm -rf "$tmpdir" 2>/dev/null
}

# ------------------------------- FILE LIST ---------------------------------
cmd_files() {
  local folder="${1:-.}"
  [[ -d "$folder" ]] || { err "Folder tidak ditemukan: $folder"; return 1; }

  echo ""
  say "File listing: $folder"
  echo ""

  find "$folder" -type f 2>/dev/null | while read -r f; do
    local sz ftype
    sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
    ftype=$(detect_file_type "$f")
    local color="$RESET"
    case "$ftype" in
      text) color="$GRN";;
      binary) color="$YLW";;
      archive|raw-disk|qcow2|vdi|vhd|vmdk|ewf|iso) color="$RED";;
      image|media) color="$MGT";;
      pcap) color="$ORG";;
      *) color="$BLU";;
    esac
    echo -e "  ${color}[$ftype]${RESET} $(numfmt --to=iec $sz 2>/dev/null || echo "${sz}B") $f"
  done | sort
}

# ------------------------------- BATCH HUNT --------------------------------
cmd_batch_hunt() {
  local file="$1"
  [[ -f "$file" ]] || { err "File tidak ditemukan: $file"; return 1; }

  echo ""
  say "Batch hunt: $file"
  info "Mencari semua pola umum CTF/forensics..."

  local patterns=(
    "flag{"
    "FLAG{"
    "KTCG"
    "CTF{"
    "secret"
    "password"
    "key"
    "hidden"
    "admin"
    "root"
    "base64"
    "http"
    "ssh"
    "ftp"
    "sql"
    "token"
    "api_key"
    "private"
    "credential"
  )

  local IFS='|'
  local re="${patterns[*]}"
  info "Combined regex: $re"
  echo ""

  "$STRINGS" -n 4 "$file" 2>/dev/null | grep -naiE "$re" 2>/dev/null | head -100 | flaghl | sed 's/^/    /'
}

# ===========================================================================
#  SMART / AUTO SEARCH  —  ketik pola pendek (.exe, jpg, flag, OMOP, 192.168)
#  -> otomatis bangkitkan SEMUA regex yang relevan + cari di nama file &
#     isi file sekaligus. Tanpa perlu nulis regex manual.
# ===========================================================================

escape_char_regex() {
  printf '%s' "$1" | sed -e 's/[.[\*^$()+?{|\\]/\\&/g'
}

# classify_pola: tebak jenis pola input -> extension/ip/url/hex/flag/flagword/word
classify_pola() {
  local p="$1"
  [[ -z "$p" ]] && { echo "empty"; return; }
  if [[ "$p" =~ ^\.[A-Za-z0-9]{1,10}$ ]]; then
    echo "extension"; return
  fi
  case "${p,,}" in
    flag|secret|key|password|token|hidden|admin|root|credential|private|login|cred|auth|user)
      echo "flagword"; return;;
  esac
  # hex murni genap >= 8 char didahulukan (mis. 4f4d4f50) sebelum extension/word
  if [[ "$p" =~ ^[0-9a-fA-F]+$ ]] && (( ${#p} % 2 == 0 )) && (( ${#p} >= 8 )); then
    echo "hex"; return
  fi
  if [[ "$p" =~ ^[a-z0-9]{1,10}$ ]]; then
    echo "extension-or-word"; return
  fi
  if [[ "$p" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    echo "ip"; return
  fi
  if [[ "$p" =~ ^https?:// ]] || [[ "$p" =~ ^[a-z0-9.-]+\.[a-z]{2,}(/|$) ]]; then
    echo "url"; return
  fi
  if [[ "$p" == *'{'* ]] || flag_matches "$p"; then
    echo "flag"; return
  fi
  echo "word"
}

# build_regexes: hasilkan baris "NAME:<regex>" / "CONTENT:<regex>"
build_regexes() {
  local p="$1" type="$2"
  local esc lit
  esc=$(escape_char_regex "$p")
  lit="${p#.}"
  lit=$(escape_char_regex "$lit")

  case "$type" in
    extension)
      echo "NAME:\\.$lit\$"
      echo "CONTENT:${esc}"
      echo "CONTENT:\\.$lit\$"
      ;;
    extension-or-word)
      echo "NAME:\\.$lit\$"
      echo "CONTENT:${lit}"
      echo "CONTENT:\\.${lit}"
      ;;
    ip|url)
      echo "CONTENT:${esc}"
      ;;
    hex)
      echo "NAME:${p,,}|${p^^}"
      echo "CONTENT:${p,,}|${p^^}"
      ;;
    flag)
      echo "CONTENT:${p}"
      ;;
    flagword|word)
      echo "NAME:${lit}"
      echo "CONTENT:${lit}"
      ;;
    *)
      echo "CONTENT:${esc}"
      ;;
  esac
}

find_files_by_regex() {
  local folder="$1" regex="$2"
  find "$folder" -type f 2>/dev/null | grep -aiE "$regex" 2>/dev/null
}

search_content() {
  local folder="$1" regex="$2"
  # file teks saja untuk grep langsung (baca via file detect)
  find "$folder" -type f 2>/dev/null | head -300 | while read -r f; do
    local ftype
    ftype=$(detect_file_type "$f")
    case "$ftype" in
      text|json|xml|html|csv|log|md)
        grep -naiE "$regex" "$f" 2>/dev/null | sed "s|^|  [${f##*/}] |" | head -10 ;;
      *) : ;;
    esac
  done
  # binary via strings
  find "$folder" -type f 2>/dev/null | head -200 | while read -r f; do
    local ftype
    ftype=$(detect_file_type "$f")
    case "$ftype" in
      text|json|xml|html|csv|log|md) continue ;;
      *)
        "$STRINGS" -n "$MINLEN" "$f" 2>/dev/null | grep -naiE "$regex" 2>/dev/null | \
          sed "s|^|  [${f##*/}] |" | head -5
        ;;
    esac
  done
}

cmd_pola() {
  local folder="$1" pola="$2"
  [[ -d "$folder" ]] || { folder="$(dirname "$folder" 2>/dev/null)"; }
  [[ -d "$folder" ]] || { err "Folder tidak ditemukan: $1"; return 1; }
  [[ -z "$pola" ]] && { err "Pola kosong"; return 1; }

  local type
  type=$(classify_pola "$pola")

  echo ""
  say "Smart search: '$pola'"
  info "Klasifikasi pola: ${MGT}$type${RESET} | Folder: ${BLU}$folder${RESET}"
  echo ""

  # Bangun daftar regex
  local re_list=()
  while IFS= read -r r; do
    [[ -n "$r" ]] && re_list+=("$r")
  done < <(build_regexes "$pola" "$type")

  info "Regex otomatis yang dibangkitkan:"
  for r in "${re_list[@]}"; do
    echo "    ${GRN}${r}${RESET}"
  done
  echo ""

  # Bagian 1: cari di NAMA file
  local name_any=0
  for r in "${re_list[@]}"; do
    [[ "$r" != NAME:* ]] && continue
    local nregex="${r#NAME:}"
    echo -e "${STYLE}== [NAMA FILE] cari: $nregex ==${RESET}"
    local hits
    hits=$(find_files_by_regex "$folder" "$nregex")
    if [[ -n "$hits" ]]; then
      name_any=1
      printf '%s\n' "$hits" | while read -r f; do
        local sz ftype
        sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
        ftype=$(detect_file_type "$f")
        echo -e "    ${GRN}[+]${RESET} $f  ($ftype, $(numfmt --to=iec $sz 2>/dev/null || echo "${sz}B"))"
      done
    else
      info "Tidak ada file dengan nama cocok"
    fi
    echo ""
  done

  # Bagian 2: cari di ISI file
  local content_any=0
  for r in "${re_list[@]}"; do
    [[ "$r" != CONTENT:* ]] && continue
    local cregex="${r#CONTENT:}"
    echo -e "${STYLE}== [ISI FILE] cari: $cregex ==${RESET}"
    local hits
    hits=$(search_content "$folder" "$cregex")
    if [[ -n "$hits" ]]; then
      content_any=1
      printf '%s\n' "$hits" | head -30 | flaghl | sed 's/^/    /'
    else
      info "Tidak ada match di isi file"
    fi
    echo ""
  done

  # Ringkasan
  echo "----------------------------------------------------------------------"
  if (( name_any == 1 || content_any == 1 )); then
    ok "Selesai. Ditemukan match pada nama dan/atau isi file."
  else
    warn "Tidak ditemukan apa pun untuk pola '$pola' (tipe: $type)."
    echo "    Coba pola lain, atau gunakan perintah spesifik (hex/deep/encode)."
  fi
}

# ------------------------------- MENU --------------------------------------
main_menu() {
  local m
  while true; do
    echo ""
    echo "======================================================================"
    echo -e "  ${STYLE}Universal Strings & Regex Toolkit${RESET}"
    echo "======================================================================"
    if [[ -n "$TARGET" ]]; then
      echo -e "  File  : ${GRN}$TARGET${RESET}  ($(detect_file_type "$TARGET"))"
    else
      echo -e "  File  : ${YLW}(belum dipilih)${RESET}"
    fi
    if [[ -n "$FOLDER" ]]; then
      echo -e "  Folder: ${GRN}$FOLDER${RESET}"
    fi
    echo -e "  Output: ${BLU}$OUTDIR_BASE${RESET}"
    echo "----------------------------------------------------------------------"
    echo -e "  ${GRN}>>> SMART SEARCH <<<${RESET}  Ketik pola (.exe/jpg/flag/OMOP/192.168)"
    echo "----------------------------------------------------------------------"
    echo "  [AUTO]    0) Smart search pola (otomatis!)"
    echo "----------------------------------------------------------------------"
    echo "  [STRING]  1) Extract strings            2) Deep search (4 method)"
    echo "            3) Batch hunt (semua pola)     4) Multi-pattern search"
    echo "  [SEARCH]  5) Regex search (single)       6) Recursive folder scan"
    echo "            7) Hex pattern search          8) Disk image search"
    echo "  [ANALYZE] 9) Detect & decode encode     10) Flag/secret hunt"
    echo "           11) File info & entropi        12) File type listing"
    echo "  [EXTRACT]13) Extract nested/embedded"
    echo "----------------------------------------------------------------------"
    echo "  F) Set file   D) Set folder   Q) Keluar"
    echo "----------------------------------------------------------------------"
    read -rp "  Pilih: " m
    case "$m" in
      0) read -rp "  Masukkan pola (.exe, jpg, flag, OMOP, 192.168...): " pola
         [[ -n "$pola" ]] && cmd_pola "${FOLDER:-.}" "$pola";;
      1) [[ -n "$TARGET" ]] && cmd_str "$TARGET" || warn "Pilih file dulu (F)";;
      2) [[ -n "$TARGET" ]] && { read -rp "  Pattern (regex): " p; [[ -n "$p" ]] && cmd_deep "$TARGET" "$p"; } || warn "Pilih file dulu (F)";;
      3) [[ -n "$TARGET" ]] && cmd_batch_hunt "$TARGET" || warn "Pilih file dulu (F)";;
      4) [[ -n "$TARGET" ]] && { read -rp "  Patterns (koma-pisah): " p; [[ -n "$p" ]] && cmd_multi "$TARGET" "$p"; } || warn "Pilih file dulu (F)";;
      5) [[ -n "$TARGET" ]] && { read -rp "  Pattern (regex): " p; [[ -n "$p" ]] && cmd_regex "$TARGET" "$p"; } || warn "Pilih file dulu (F)";;
      6) [[ -n "$FOLDER" ]] && { read -rp "  Pattern (regex): " p; [[ -n "$p" ]] && cmd_scan "$FOLDER" "$p"; } || { [[ -n "$TARGET" ]] && { read -rp "  Pattern (regex): " p; [[ -n "$p" ]] && cmd_scan "$(dirname "$TARGET")" "$p"; } || warn "Pilih folder dulu (D)"; };;
      7) [[ -n "$TARGET" ]] && { read -rp "  Hex pattern (ex: 4b544347): " p; [[ -n "$p" ]] && cmd_hex "$TARGET" "$p"; } || warn "Pilih file dulu (F)";;
      8) [[ -n "$TARGET" ]] && { read -rp "  Pattern (regex): " p; [[ -n "$p" ]] && cmd_disk "$TARGET" "$p"; } || warn "Pilih file dulu (F)";;
      9) [[ -n "$TARGET" ]] && cmd_encode "$TARGET" || warn "Pilih file dulu (F)";;
     10) [[ -n "$TARGET" ]] && cmd_flag "$TARGET" || warn "Pilih file dulu (F)";;
     11) [[ -n "$TARGET" ]] && cmd_stat "$TARGET" || warn "Pilih file dulu (F)";;
     12) cmd_files "${FOLDER:-.}";;
     13) [[ -n "$TARGET" ]] && cmd_nest "$TARGET" || warn "Pilih file dulu (F)";;
      [fF]) read -rp "  Path file: " p; [[ -n "$p" && -f "$(resolve "$p")" ]] && TARGET="$(resolve "$p")" && ok "File: $TARGET" || err "File tidak ditemukan: $p";;
      [dD]) read -rp "  Path folder: " p; [[ -n "$p" && -d "$p" ]] && FOLDER="$(resolve "$p")" && ok "Folder: $FOLDER" || err "Folder tidak ditemukan: $p";;
      [qQ]) echo "  Sampai jumpa."; exit 0;;
      *) warn "Pilihan tidak dikenal: $m";;
    esac
  done
}

# ------------------------------ DISPATCH -----------------------------------
usage() {
  echo ""
  echo "Cara pakai:"
  echo "  $0                                       -> menu interaktif"
  echo "  $0 <file>                                -> strings cepat"
  echo "  $0 pola <folder> <pola>                  -> SMART search (otomatis!)"
  echo "  $0 str <file> [minlen]                   -> extract strings"
  echo "  $0 regex <file> <pattern>                -> regex search"
  echo "  $0 flag <file>                           -> hunt flag/secret"
  echo "  $0 scan <folder> <pattern>               -> recursive search"
  echo "  $0 hex <file> <hex-pattern>              -> cari hex di binary"
  echo "  $0 nest <file>                           -> extract embedded files"
  echo "  $0 multi <file> <pola1,pola2,...>        -> multi-pattern search"
  echo "  $0 encode <file>                         -> deteksi string ter-encode"
  echo "  $0 stat <file>                           -> info & entropi"
  echo "  $0 deep <file> <pattern>                 -> deep search (4 method)"
  echo "  $0 disk <disk-image> <pattern>           -> search di disk image"
  echo "  $0 files [folder]                        -> list files + tipe"
  echo "  $0 batch <file>                          -> batch hunt semua pola"
  echo ""
  echo "Flag prefix (opsional):"
  echo "  $0 --prefix 'KTCG,CTF,{}' flag <file>"
  echo "  export FLAGPREFIX='KTCG,MyCTF,flag'"
  echo ""
  echo "Support: teks, binary, ELF/PE, disk image (.img/.dd), virtual disk"
  echo "         (vmdk/vdi/vhd/qcow2), arsip (zip/7z/gz), E01, ISO, pcap,"
  echo "         PDF, gambar, database, dan semua tipe file."
  echo ""
  echo "Requires: file, strings, grep, xxd, python3"
  echo "Optional: binwalk, 7z"
}

# ----------------------------- MAIN ---------------------------------------
main() {
  local CLI_PREFIX=""
  local args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --prefix|-p) CLI_PREFIX="${2:-}"; shift 2;;
      *) args+=("$1"); shift;;
    esac
  done
  set -- "${args[@]}"
  export CLI_PREFIX
  load_flag_prefix
  ensure_outdir

  # --- bentuk 1: $0 <cmd> <file> [args] ---
  if [[ $# -ge 1 ]]; then
    case "$1" in
      -h|--help|help) usage; exit 0;;
      pola)
        [[ $# -ge 3 ]] || { err "Usage: $0 pola <folder> <pola>"; exit 1; }
        FOLDER="$(resolve "$2")"
        cmd_pola "$FOLDER" "$3"
        exit 0;;
      str)
        [[ $# -ge 2 ]] || { err "Usage: $0 str <file> [minlen]"; exit 1; }
        TARGET="$(resolve "$2")"
        cmd_str "$TARGET" "${3:-$MINLEN}"
        exit 0;;
      regex)
        [[ $# -ge 3 ]] || { err "Usage: $0 regex <file> <pattern>"; exit 1; }
        TARGET="$(resolve "$2")"
        cmd_regex "$TARGET" "$3"
        exit 0;;
      flag)
        [[ $# -ge 2 ]] || { err "Usage: $0 flag <file>"; exit 1; }
        TARGET="$(resolve "$2")"
        cmd_flag "$TARGET"
        exit 0;;
      scan)
        [[ $# -ge 3 ]] || { err "Usage: $0 scan <folder> <pattern>"; exit 1; }
        FOLDER="$(resolve "$2")"
        cmd_scan "$FOLDER" "$3"
        exit 0;;
      hex)
        [[ $# -ge 3 ]] || { err "Usage: $0 hex <file> <hex-pattern>"; exit 1; }
        TARGET="$(resolve "$2")"
        cmd_hex "$TARGET" "$3"
        exit 0;;
      nest)
        [[ $# -ge 2 ]] || { err "Usage: $0 nest <file>"; exit 1; }
        TARGET="$(resolve "$2")"
        cmd_nest "$TARGET"
        exit 0;;
      multi)
        [[ $# -ge 3 ]] || { err "Usage: $0 multi <file> <pola1,pola2,...>"; exit 1; }
        TARGET="$(resolve "$2")"
        cmd_multi "$TARGET" "$3"
        exit 0;;
      encode)
        [[ $# -ge 2 ]] || { err "Usage: $0 encode <file>"; exit 1; }
        TARGET="$(resolve "$2")"
        cmd_encode "$TARGET"
        exit 0;;
      stat)
        [[ $# -ge 2 ]] || { err "Usage: $0 stat <file>"; exit 1; }
        TARGET="$(resolve "$2")"
        cmd_stat "$TARGET"
        exit 0;;
      deep)
        [[ $# -ge 3 ]] || { err "Usage: $0 deep <file> <pattern>"; exit 1; }
        TARGET="$(resolve "$2")"
        cmd_deep "$TARGET" "$3"
        exit 0;;
      disk)
        [[ $# -ge 3 ]] || { err "Usage: $0 disk <image> <pattern>"; exit 1; }
        TARGET="$(resolve "$2")"
        cmd_disk "$TARGET" "$3"
        exit 0;;
      files)
        FOLDER="${2:-.}"
        FOLDER="$(resolve "$FOLDER")"
        cmd_files "$FOLDER"
        exit 0;;
      batch)
        [[ $# -ge 2 ]] || { err "Usage: $0 batch <file>"; exit 1; }
        TARGET="$(resolve "$2")"
        cmd_batch_hunt "$TARGET"
        exit 0;;
    esac
  fi

  # --- bentuk 2: $0 <file> -> strings cepat ---
  if [[ $# -ge 1 && -f "$(resolve "$1")" ]]; then
    TARGET="$(resolve "$1")"
    if [[ $# -eq 1 ]]; then
      echo ""
      say "Quick strings: $TARGET"
      cmd_str "$TARGET"
      echo ""
      info "Gunakan 'menu' untuk mode interaktif:  $0 menu"
      exit 0
    fi
    # $0 <file> <cmd> [args]
    case "$2" in
      str)   cmd_str "$TARGET" "${3:-$MINLEN}";;
      regex) cmd_regex "$TARGET" "${3:-}";;
      flag)  cmd_flag "$TARGET";;
      hex)   cmd_hex "$TARGET" "${3:-}";;
      nest)  cmd_nest "$TARGET";;
      encode) cmd_encode "$TARGET";;
      stat)  cmd_stat "$TARGET";;
      deep)  cmd_deep "$TARGET" "${3:-}";;
      *) err "Sub-perintah '$2' tidak dikenal"; usage; exit 1;;
    esac
    exit 0
  fi

  # --- tidak ada argumen atau cmd tidak dikenal -> menu ---
  if [[ $# -ge 1 ]]; then
    # coba treat sebagai file
    if [[ -f "$(resolve "$1")" ]]; then
      TARGET="$(resolve "$1")"
      cmd_str "$TARGET"
      exit 0
    fi
    err "Usage: $0 [file] | <cmd> <file> [args] | -h"
    exit 1
  fi
  main_menu
}

main "$@"
