#!/usr/bin/env bash
# =============================================================================
#  Carver - Generic CTF Hex/Binary File Carver
#  --------------------------------------------------------------------------
#  Fitur:
#   - Auto-detect input HEX text vs binary
#   - Tanpa argumen -> menu interaktif (auto-cari file, pilih jenis, output)
#   - Scan & carve embedded file dengan banyak signature format
#   - Pengambilan berbasis footer (SOI/EOI, IEND, %%EOF, PK.End, dll)
#   - Mode direct:  ./carver.sh file.hex          -> carve semua + verifikasi
#   - Mode filter:  ./carver.sh file.bin -f jpg   -> hanya format tertentu
#   - Mode output:  ./carver.sh file.bin -o hasil  -> output ke ./hasil
#   - Output default di ./carved (working directory), bukan /tmp
#   - Simpan output ke log dengan timestamp
#
#  Cara pakai:
#     ./carver.sh                                 -> interaktif (pilih file)
#     ./carver.sh file.hex                        -> carve & list hasil
#     ./carver.sh file.bin -f jpg                 -> hanya JPEG
#     ./carver.sh file.bin -o hasil               -> output ke ./hasil
#     ./carver.sh file.bin -i                     -> masuk menu setelah scan
#
#  Requirement: xxd, dd, grep, tr (tools inti, selalu tersedia di distro)
# =============================================================================

set -uo pipefail

# ----------------------------- KONFIGURASI --------------------------------
# Output default relatif working-directory (bukan /tmp): ./carved
CARVE_DIR_NAME="carved"
CACHE_DIR_NAME=".carver_cache"
OUTDIR_BASE="$PWD/$CARVE_DIR_NAME"
STYLE="\e[1;36m"; RESET="\e[0m"
RED="\e[1;31m"; GRN="\e[1;32m"; YLW="\e[1;33m"; BLU="\e[1;34m"

# ----------------------------- UTILITAS -----------------------------------

say()  { echo -e "${STYLE}[*]${RESET} $*"; }
ok()   { echo -e "${GRN}[+]${RESET} $*"; }
warn() { echo -e "${YLW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[-]${RESET} $*"; }

resolve() {
  local p="$1"
  if [[ "$p" != /* ]]; then p="$(pwd)/$p"; fi
  echo "$p"
}

# hex text -> binary. tr buang whitespace; xxd -r -p decode
hex_to_bin() {
  local src="$1" dst="$2"
  tr -d '\r\n\t ' < "$src" | xxd -r -p > "$dst"
}

# is_hex_text <file> : seluruh isi (tanpa whitespace) murni hex & panjang genap.
# Dihitung lewat wc (bukan disimpan ke variabel) agar aman bila isi ada NUL.
is_hex_text() {
  local f="$1" stripped hvz
  [[ -s "$f" ]] || return 1
  stripped="$(tr -d ' \t\r\n' < "$f" | wc -c)"
  hvz="$(tr -cd '0-9a-fA-F' < "$f" | wc -c)"
  [[ "$stripped" -eq "$hvz" ]] || return 1   # ada karakter non-hex
  [[ $(( stripped % 2 )) -eq 0 ]] || return 1
  return 0
}

# ----------------------------- SIGNATURES --------------------------------
# Setiap format: descriptor (desc) + hex header (hdr) + hex footer (ftr).
# Header literal di-scan byte-per-byte; footer dipakai sebagai penutup slice.
# Format dengan header ambigu (RIFF, cafebabe) dibedakan footer; bila tanpa
# footer, hasil "sampai akhir file" (false positive wajar utk carving).
declare -A FMT_DESC FMT_HDR FMT_FTR

FMT_DESC[jpg]="JPEG image"          ; FMT_HDR[jpg]="ffd8ff"            ; FMT_FTR[jpg]="ffd9"
FMT_DESC[png]="PNG image"           ; FMT_HDR[png]="89504e470d0a1a0a"    ; FMT_FTR[png]="49454e44ae426082"
FMT_DESC[gif]="GIF image"           ; FMT_HDR[gif]="4749463837"         ; FMT_FTR[gif]="3b"
FMT_DESC[bmp]="BMP image"           ; FMT_HDR[bmp]="424d"               ; FMT_FTR[bmp]=""
FMT_DESC[webp]="WebP image"         ; FMT_HDR[webp]="52494646"          ; FMT_FTR[webp]=""
FMT_DESC[ico]="ICO/CUR icon"        ; FMT_HDR[ico]="00000100"           ; FMT_FTR[ico]=""
FMT_DESC[pdf]="PDF document"        ; FMT_HDR[pdf]="25504446"           ; FMT_FTR[pdf]="2525454f46"
FMT_DESC[zip]="ZIP archive"         ; FMT_HDR[zip]="504b0304"           ; FMT_FTR[zip]="504b0506"
FMT_DESC[gzip]="GZIP archive"       ; FMT_HDR[gzip]="1f8b08"            ; FMT_FTR[gzip]=""
FMT_DESC[bz2]="BZip2 archive"       ; FMT_HDR[bz2]="425a68"             ; FMT_FTR[bz2]=""
FMT_DESC[xz]="XZ archive"           ; FMT_HDR[xz]="fd377a585a00"        ; FMT_FTR[xz]=""
FMT_DESC[rar]="RAR archive"         ; FMT_HDR[rar]="526172211a0700"     ; FMT_FTR[rar]=""
FMT_DESC[7z]="7-Zip archive"        ; FMT_HDR[7z]="377abcaf271c"        ; FMT_FTR[7z]=""
FMT_DESC[elf]="ELF executable"      ; FMT_HDR[elf]="7f454c46"           ; FMT_FTR[elf]=""
FMT_DESC[exe]="Windows exe (MZ)"    ; FMT_HDR[exe]="4d5a"               ; FMT_FTR[exe]=""
FMT_DESC[class]="Java class"        ; FMT_HDR[class]="cafebabe"         ; FMT_FTR[class]=""
FMT_DESC[wav]="WAV audio"           ; FMT_HDR[wav]="52494646"           ; FMT_FTR[wav]=""
FMT_DESC[mp3]="MP3 audio"           ; FMT_HDR[mp3]="494433"             ; FMT_FTR[mp3]=""
FMT_DESC[asf]="ASF/WMV video"       ; FMT_HDR[asf]="3026b2758e66cf11"   ; FMT_FTR[asf]=""
FMT_DESC[rtf]="Rich Text"           ; FMT_HDR[rtf]="7b5c727466"         ; FMT_FTR[rtf]=""
FMT_DESC[sqlite]="SQLite database"  ; FMT_HDR[sqlite]="53514c69746520666f726d6174203300" ; FMT_FTR[sqlite]=""

# Daftar default urutan scan. Ambigu header (RIFF/cafebabe) diguide footer.
ALL_FORMATS=( jpg png gif pdf zip gzip bz2 xz rar 7z elf exe class webp wav mp3 asf rtf sqlite bmp ico )

# ----------------------------- CARVE ENGINE ------------------------------

CARVED=()         # "filetype|offset|size|end|path"
CARVE_COUNT=0

# blob_to_hex <blob> : output seluruh isi sbg hex kontinu (tanpa newline)
blob_to_hex() {
  xxd -p -c1 "$1" | tr -d '\n'
}

# find_all <hex-header> <blob> : cetak offset byte (decimal) tiap match, 1/baris.
# Scan memakai representasi hex (ASCII, bebas NUL) lalu filter offset genap
# supaya hanya match yang benar-benar sejajar byte.
find_all() {
  local hdr="$1" blob="$2" hx p
  hx="$(blob_to_hex "$blob")"
  while IFS=: read -r p _; do
    [[ $(( p % 2 )) -eq 0 ]] && echo $(( p / 2 ))
  done < <(grep -aboF "$hdr" <<<"$hx")
}

# find_footer_pos <hex-footer> <blob> <from> : offset absolut footer pertama >=
# 'from', atau -1 bila tak ada. Jendela dibatasi 16MB agak tidak boros memori.
find_footer_pos() {
  local ftr="$1" blob="$2" from="$3"
  local flen=$(( ${#ftr} / 2 )) hx p
  hx="$(dd if="$blob" iflag=skip_bytes skip="$from" bs=1M count=16 \
    status=none 2>/dev/null | xxd -p -c1 | tr -d '\n')"
  p="$(grep -aboF "$ftr" <<<"$hx" | head -1 | cut -d: -f1)"
  if [[ -n "$p" ]] && [[ $(( p % 2 )) -eq 0 ]]; then
    echo $(( from + p / 2 + flen ))
  else
    echo "-1"
  fi
}

# carvescan <blob> [fmt...] : isi CARVED dgn semua temuan (tanpa menulis file)
carvescan() {
  local blob="$1"; shift
  local fmts=()
  if [[ $# -gt 0 ]]; then fmts=("$@"); else fmts=("${ALL_FORMATS[@]}"); fi

  local total; total="$(stat -c%s "$blob")"
  local ft hdr ftr off end size found name
  CARVED=(); CARVE_COUNT=0

  for ft in "${fmts[@]}"; do
    hdr="${FMT_HDR[$ft]:-}"
    ftr="${FMT_FTR[$ft]:-}"
    [[ -n "$hdr" ]] || continue
    while IFS= read -r off; do
      [[ "$off" =~ ^[0-9]+$ ]] || continue
      off=$((off))
      end="$total"
      if [[ -n "$ftr" ]]; then
        found="$(find_footer_pos "$ftr" "$blob" "$off")"
        [[ "$found" -ge 0 ]] && end="$found"
      fi
      size=$(( end - off ))
      [[ "$size" -le 0 ]] && continue
      name="extracted_$(printf '%03d' $((CARVE_COUNT+1))).$ft"
      CARVED+=( "$ft|$off|$size|$end|$OUTDIR/$name" )
      CARVE_COUNT=$((CARVE_COUNT+1))
    done < <(find_all "$hdr" "$blob")
  done
}

# carve_write <blob> <idx> : tulis hasil idx -> file, cetak "ft|off|size|end|path"
carve_write() {
  local blob="$1" idx="$2" rec
  rec="${CARVED[$idx]}"
  local ft off size end path out
  IFS='|' read -r ft off size end path <<< "$rec"
  out="$path"
  mkdir -p "$(dirname "$out")"
  dd if="$blob" of="$out" bs=1 skip="$off" count="$size" status=none 2>/dev/null
  printf '%s|%s|%s|%s|%s\n' "$ft" "$off" "$size" "$end" "$out"
}

list_carved() {
  if [[ "$CARVE_COUNT" -eq 0 ]]; then
    warn "Tidak ada signature ditemukan."
    return
  fi
  echo ""
  echo "  Hasil scan ($CARVE_COUNT signature):"
  echo "  ------------------------------------------------------------------"
  local i rec ft off size path
  for i in "${!CARVED[@]}"; do
    rec="${CARVED[$i]}"
    IFS='|' read -r ft off size end path <<< "$rec"
    printf "  [%2d] %-6s offset=0x%-6x size=%-8d %s\n" \
      "$((i+1))" "$ft" "$off" "$size" "$path"
  done
  echo "  ------------------------------------------------------------------"
}

# ----------------------------- MENU INTERAKTIF ---------------------------

main_menu() {
  while true; do
    echo ""
    echo "======================================================================"
    echo -e "  ${STYLE}Carver - CTF File Carver${RESET}"
    echo "======================================================================"
    echo -e "  Input : ${GRN}${BLOB}${RESET}  (${INPUT_KIND})"
    echo -e "  Outdir: ${BLU}${OUTDIR}${RESET}"
    echo -e "  Hasil : ${YLW}${CARVE_COUNT} signature${RESET}"
    echo "----------------------------------------------------------------------"
    echo "  1) Scan ulang (semua format)    2) Scan ulang (filter format)"
    echo "  3) Tulis satu hasil              4) Tulis semua hasil"
    echo "  5) Ganti file input              6) Ganti output dir"
    echo "  7) Info input"
    echo "----------------------------------------------------------------------"
    echo "  L) Toggle save-to-log  |  Q) Keluar"
    echo "----------------------------------------------------------------------"
    read -rp "Pilih menu: " m
    case "$m" in
      1) carvescan "$BLOB"; list_carved;;
      2) menu_format_filter;;
      3) menu_carve_one;;
      4) menu_carve_all;;
      5) menu_change_input;;
      6) menu_change_outdir;;
      7) info_input;;
      [lL]) toggle_log;;
      [qQ]) exit 0;;
      *) warn "Pilihan tidak dikenal: $m";;
    esac
  done
}

menu_format_filter() {
  echo ""
  echo "  Pilih format target:"
  local fmts=( "all" "${ALL_FORMATS[@]}" ) i
  for i in "${!fmts[@]}"; do
    printf "    [%2d] %-8s %s\n" "$((i+1))" "${fmts[$i]}" "${FMT_DESC[${fmts[$i]}]:-}"
  done
  read -rp "  Pilih: " s
  [[ "$s" =~ ^[0-9]+$ ]] || { warn "Batal"; return; }
  local pick="${fmts[$((s-1))]:-}"
  if [[ -z "$pick" ]]; then warn "Batal"; return; fi
  if [[ "$pick" == "all" ]]; then carvescan "$BLOB"; else carvescan "$BLOB" "$pick"; fi
  list_carved
}

menu_carve_one() {
  read -rp "  Nomor hasil yang mau ditulis [kosong=semua]: " n
  if [[ -z "$n" ]]; then menu_carve_all; return; fi
  if [[ ! "$n" =~ ^[0-9]+$ ]] || (( n < 1 || n > CARVE_COUNT )); then
    err "Nomor invalid (1-$CARVE_COUNT)."; return
  fi
  local rec ft off size end path
  rec="$(carve_write "$BLOB" $((n-1)))"
  IFS='|' read -r ft off size end path <<< "$rec"
  ok "Ditulis: $path ($size bytes)"
  command -v file >/dev/null 2>&1 && file "$path"
}

menu_carve_all() {
  local i
  for i in "${!CARVED[@]}"; do
    carve_write "$BLOB" "$i" >/dev/null
  done
  ok "Semua hasil ditulis ke: $OUTDIR"
  ls -1 "$OUTDIR"
}

# write_all_carved() : tulis semua hasil carve ke disk + tampilkan satu/baris.
write_all_carved() {
  local i rec ft off size end path
  if [[ "$CARVE_COUNT" -eq 0 ]]; then
    warn "Tidak ada hasil untuk ditulis."
    return
  fi
  ok "Menulis $CARVE_COUNT hasil ke: $OUTDIR"
  for i in "${!CARVED[@]}"; do
    rec="$(carve_write "$BLOB" "$i")"
    IFS='|' read -r ft off size end path <<< "$rec"
    printf "  [+]\e[1;32m %-6s\e[0m offset=0x%-6x size=%-8d -> %s\n" \
      "$ft" "$off" "$size" "$path"
  done
}

menu_change_outdir() {
  read -rp "  Output dir baru [default $OUTDIR_BASE]: " d
  if [[ -z "$d" ]]; then
    OUTDIR="$OUTDIR_BASE"
  else
    OUTDIR="$(resolve "$d")"
  fi
  mkdir -p "$OUTDIR"
  ok "Output dir -> $OUTDIR"
}

menu_change_input() {
  read -rp "  Path file baru [kosong=cari otomatis]: " bf
  if [[ -z "$bf" ]]; then
    pick_file
    load_input "$BLOB_SRC"
    if [[ -n "$FORMAT_FILTER" ]]; then carvescan "$BLOB" "$FORMAT_FILTER"; else carvescan "$BLOB"; fi
    list_carved
    return
  fi
  bf="$(resolve "$bf")"
  [[ -f "$bf" ]] || { err "File tidak ditemukan: $bf"; return; }
  load_input "$bf"
}

# CARVE_CANDS : path-file kandidat (diisi pick_file).
CARVE_CANDS=()

# pick_file() : auto-cari file kandidat di direktori & subdir, lalu pilih.
pick_file() {
  mapfile -t CARVE_CANDS < <(
    find "$(pwd)" -maxdepth 3 -type f \( -iname '*.bin' -o -iname '*.hex' \
      -o -iname '*.raw' -o -iname '*.img' -o -iname '*.dat' \
      -o -iname '*.pcap' -o -iname '*.pcapng' -o -iname '*.mem' \
      -o -iname '*.dmp' \) 2>/dev/null | sort -u
  )
  if [[ ${#CARVE_CANDS[@]} -eq 0 ]]; then
    err "Tidak ada file carving ditemukan di $(pwd) (maxdepth 3)."
    read -rp "  Ketik path file manual (atau Enter untuk batal): " manual
    [[ -n "$manual" ]] || { err "Batal."; exit 1; }
    manual="$(resolve "$manual")"
    [[ -f "$manual" ]] || { err "File tidak ditemukan: $manual"; exit 1; }
    CARVE_CANDS=( "$manual" )
  fi

  echo ""
  echo "  File kandidat ditemukan (${#CARVE_CANDS[@]}):"
  echo "  ------------------------------------------------------------------"
  local i f size
  for i in "${!CARVE_CANDS[@]}"; do
    f="${CARVE_CANDS[$i]}"
    size="$(stat -c%s "$f" 2>/dev/null)"
    printf "  [%2d] %-4s %s  (%s bytes)\n" \
      "$((i+1))" "$(is_hex_text "$f" && echo HEX || echo BIN)" "$f" "${size:-?}"
  done
  echo "  ------------------------------------------------------------------"
  read -rp "  Pilih nomor file [1-${#CARVE_CANDS[@]}]: " sel
  if [[ ! "$sel" =~ ^[0-9]+$ ]] || (( sel < 1 || sel > ${#CARVE_CANDS[@]} )); then
    err "Pilihan tidak valid."
    exit 1
  fi
  BLOB_SRC="${CARVE_CANDS[$((sel-1))]}"
}

# pick_format() : tanya apakah mau filter format tertentu (atau scan semua).
pick_format() {
  echo ""
  echo "  Scan format:"
  echo "    [ 0] all   (semua format)"
  local i
  for i in "${!ALL_FORMATS[@]}"; do
    printf "    [%2d] %-8s %s\n" "$((i+1))" "${ALL_FORMATS[$i]}" "${FMT_DESC[${ALL_FORMATS[$i]}]:-}"
  done
  read -rp "  Pilih format [kosong=all]: " s
  FORMAT_FILTER=""
  if [[ -z "$s" || "$s" == "0" ]]; then
    return
  fi
  local pick=""
  if [[ "$s" =~ ^[0-9]+$ ]]; then pick="${ALL_FORMATS[$((s-1))]:-}"; fi
  if [[ -n "$pick" ]]; then
    FORMAT_FILTER="$pick"
    ok "Filter format: $pick"
  else
    warn "Pilihan tidak dikenal -> scan semua format."
  fi
}

# pick_outdir() : tanya lokasi output, default ./carved
pick_outdir() {
  echo ""
  read -rp "  Letakkan hasil di folder [default: $OUTDIR_BASE]: " d
  if [[ -z "$d" ]]; then
    OUTDIR="$OUTDIR_BASE"
  else
    OUTDIR="$(resolve "$d")"
  fi
  mkdir -p "$OUTDIR"
  ok "Output dir -> $OUTDIR"
}

toggle_log() {
  if [[ "$SAVE_LOG" == "1" ]]; then
    SAVE_LOG=0; LOGFILE=""; warn "Save-to-log: OFF"
  else
    SAVE_LOG=1
    LOGFILE="$OUTDIR/session_$(date +%Y%m%d_%H%M%S).log"
    mkdir -p "$OUTDIR"
    : > "$LOGFILE"
    ok "Save-to-log: ON -> $LOGFILE"
  fi
}

info_input() {
  echo -e "  Input file : ${GRN}${BLOB}${RESET}"
  echo "  Tipe input : ${INPUT_KIND}"
  echo "  Ukuran     : $(stat -c%s "$BLOB") bytes"
  command -v file >/dev/null 2>&1 && echo "  file(1)    : $(file -b "$BLOB")"
}

# ----------------------------- MAIN ---------------------------------------

# global state
OUTDIR="$OUTDIR_BASE"
SAVE_LOG=0
LOGFILE=""
FORMAT_FILTER=""
INTERACTIVE=0
INPUT_KIND=""
BLOB=""
BLOB_SRC=""

# load_input <path> : setup BLOB (auto hex->bin), INPUT_KIND, OUTDIR
load_input() {
  local src="$1" tmp
  BLOB="$(resolve "$src")"
  if is_hex_text "$BLOB"; then
    INPUT_KIND="HEX text"
    tmp="$PWD/$CACHE_DIR_NAME/hex_$$.bin"
    mkdir -p "$(dirname "$tmp")"
    hex_to_bin "$BLOB" "$tmp"
    BLOB="$tmp"
    say "Input terdeteksi sebagai HEX text -> $BLOB"
  else
    INPUT_KIND="binary"
    say "Input terdeteksi sebagai binary"
  fi
  mkdir -p "$OUTDIR"
  ok "Loaded: $(stat -c%s "$BLOB") bytes"
}

usage() {
  echo "Usage: $0 [file] [-f format] [-o dir] [-i]"
  echo ""
  echo "  (tanpa file)            buka mode interaktif: pilih file, jenis, output"
  echo "  file.hex|file.bin       carve langsung (mode direct)"
  echo "  -f, --format <fmt>      hanya scan format tertentu (jpg,png,pdf,dll)"
  echo "  -o, --output <dir>      folder output (default ./$CARVE_DIR_NAME)"
  echo "  -i, --interactive       setelah scan langsung masuk menu bukan keluar"
  echo ""
  echo "Format yang didukung:"
  printf '  %s\n' "${ALL_FORMATS[*]}"
}

SRC=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--format) FORMAT_FILTER="${2:-}"; shift 2;;
    -o|--output) OUTDIR="${2:-}"; shift 2;;
    -i|--interactive) INTERACTIVE=1; shift;;
    -h|--help) usage; exit 0;;
    -*) err "Argumen tidak dikenal: $1"; usage; exit 1;;
    *) SRC="$1"; shift;;
  esac
done

# Tanpa argumen file -> mode interaktif: pilih file, jenis, output, lalu menu.
if [[ -z "$SRC" ]]; then
  echo ""
  echo "======================================================================"
  echo -e "  ${STYLE}Carver - CTF File Carver${RESET}"
  echo "======================================================================"
  pick_file
  pick_format
  pick_outdir
  load_input "$BLOB_SRC"
  if [[ -n "$FORMAT_FILTER" ]]; then carvescan "$BLOB" "$FORMAT_FILTER"; else carvescan "$BLOB"; fi
  list_carved
  write_all_carved
  main_menu
fi

# ---------- mode direct (ada argumen file) ----------
[[ -f "$SRC" ]] || { err "File tidak ditemukan: $SRC"; exit 1; }

# -o bisa relatif -> jadikan absolut biar konsisten
OUTDIR="$(resolve "$OUTDIR")"

load_input "$SRC"

if [[ -n "$FORMAT_FILTER" ]]; then
  [[ -n "${FMT_HDR[$FORMAT_FILTER]:-}" ]] || { err "Format tidak dikenal: $FORMAT_FILTER"; exit 1; }
  carvescan "$BLOB" "$FORMAT_FILTER"
else
  carvescan "$BLOB"
fi

if (( INTERACTIVE == 1 )); then
  list_carved
  write_all_carved
  main_menu
fi

# ---------- carikan & tulis hasil ----------
if [[ "$CARVE_COUNT" -eq 0 ]]; then
  err "Tidak ditemukan embedded file."
  # bersihkan cache hex bila dibuat
  rm -rf "$PWD/$CACHE_DIR_NAME" 2>/dev/null || true
  exit 0
fi

echo ""
say "Scanning..."
echo ""
say "Ditemukan $CARVE_COUNT signature"
echo ""
i=0; rec=""; ft=""; off=""; size=""; end=""; path=""
for i in "${!CARVED[@]}"; do
  rec="$(carve_write "$BLOB" "$i")"
  IFS='|' read -r ft off size end path <<< "$rec"
  printf "  [+]\e[1;32m %-6s\e[0m offset=0x%-6x size=%-8d -> %s\n" \
    "$ft" "$off" "$size" "$path"
done

echo ""
ok "Output directory: $OUTDIR"
echo ""
if command -v file >/dev/null 2>&1; then
  say "Verifikasi (file 1):"
  i=""
  for i in "${!CARVED[@]}"; do
    IFS='|' read -r ft off size end path <<< "${CARVED[$i]}"
    printf "  %s\n    %s\n" "$path" "$(file -b "$path")"
  done
fi

# bersihkan cache hex-text yang dibuat tadi agar tidak berantakan
rm -rf "$PWD/$CACHE_DIR_NAME" 2>/dev/null || true