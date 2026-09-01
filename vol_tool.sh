#!/usr/bin/env bash
# =============================================================================
#  Volatility 3 - Interactive Memory Forensics Toolkit
#  --------------------------------------------------------------------------
#  Fitur:
#   - Auto-detect OS image (Windows / Linux / macOS)
#   - Menu interaktif bernomor per kategori plugin
#   - Dump proses / file / registry
#   - String search di memory & dump proses
#   - Simpan output ke file log dengan timestamp
#
#  Cara pakai:
#     ./vol_tool.sh                          -> interaktif (pilih file)
#     ./vol_tool.sh /path/to/image.mem       -> langsung pakai image tsb
#     ./vol_tool.sh /path/image.mem pslist   -> jalankan langsung plugin
#
#  Requirement: vol (Volatility 3) sudah ada di PATH
# =============================================================================

set -uo pipefail

# ----------------------------- KONFIGURASI --------------------------------
VOL="vol"                     # binary volatility 3
OUTDIR_BASE="/tmp/vol_result" # folder output default (ubah kalau mau)
STYLE="\e[1;36m"; RESET="\e[0m"
RED="\e[1;31m"; GRN="\e[1;32m"; YLW="\e[1;33m"; BLU="\e[1;34m"

# ----------------------------- UTILITAS -----------------------------------

say()  { echo -e "${STYLE}[*]${RESET} $*"; }
ok()   { echo -e "${GRN}[+]${RESET} $*"; }
warn() { echo -e "${YLW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[-]${RESET} $*"; }

# Path resolver: terima absolut atau relatif
resolve() {
  local p="$1"
  # jika tidak diawali / dan bukan relatif menuju file yang ada, coba bikin absolut
  if [[ "$p" != /* ]]; then
    p="$(pwd)/$p"
  fi
  echo "$p"
}

# vol3 punya windows.info.Info, tapi TIDAK punya linux.info/mac.info.
# Penggantinya untuk deteksi OS Linux/macOS:
#   linux -> linux.lsmod.Lsmod   |   mac -> mac.lsmod.Lsmod
detect_os() {
  local img="$1"
  if "$VOL" -f "$img" windows.info.Info >/dev/null 2>&1; then
    echo "windows"
  elif "$VOL" -f "$img" linux.lsmod.Lsmod >/dev/null 2>&1; then
    echo "linux"
  elif "$VOL" -f "$img" mac.lsmod.Lsmod >/dev/null 2>&1; then
    echo "mac"
  else
    echo "unknown"
  fi
}

# run_plugin <plugin> [extra vol args...]
run_plugin() {
  local plugin="$1"; shift
  echo ""
  say "Running: $plugin"
  say "Command: $VOL -f $IMAGE $plugin $*"
  if [[ "$SAVE_LOG" == "1" && -n "$LOGFILE" ]]; then
    "$VOL" -q -f "$IMAGE" "$plugin" "$@" 2>&1 | tee -a "$LOGFILE"
  else
    "$VOL" -q -f "$IMAGE" "$plugin" "$@" 2>&1
  fi
  echo ""
}

# run_plugin_dump <plugin> <extra vol args...> -> letakkan -o OUTDIR sebelum plugin
# (vol3 mengharuskan opsi global seperti -o ditulis SEBELUM nama plugin)
run_plugin_dump() {
  local plugin="$1"; shift
  echo ""
  say "Running: $plugin (output -> $OUTDIR)"
  if [[ "$SAVE_LOG" == "1" && -n "$LOGFILE" ]]; then
    "$VOL" -q -f "$IMAGE" -o "$OUTDIR" "$plugin" "$@" 2>&1 | tee -a "$LOGFILE"
  else
    "$VOL" -q -f "$IMAGE" -o "$OUTDIR" "$plugin" "$@" 2>&1
  fi
  echo ""
}

# ----------------------------- VARIABEL GLOBAL ----------------------------
IMAGE=""
OS=""
SAVE_LOG=0
LOGFILE=""
OUTDIR="$OUTDIR_BASE/vol_$$"

ensure_outdir() {
  mkdir -p "$OUTDIR" 2>/dev/null
}

init() {
  # cek vol ada
  if ! command -v "$VOL" >/dev/null 2>&1; then
    err "Volatility 3 ('$VOL') tidak ditemukan di PATH."
    exit 1
  fi

  # IMAGE dari arg pertama (kalau ada & berupa file)
  if [[ $# -ge 1 && -f "$1" ]]; then
    IMAGE="$(resolve "$1")"
    shift
  fi

  # jika ada sisa arg & itu plugin -> jalankan langsung
  if [[ $# -ge 1 && -n "$IMAGE" ]]; then
    run_plugin_direct "$@"
    exit 0
  fi
}

run_plugin_direct() {
  say "Image: $IMAGE"
  OS="$(detect_os "$IMAGE")"
  ok "Detected OS: $OS"
  run_plugin "$@"
}

# Pilih file image (interaktif)
pick_image() {
  if [[ -n "$IMAGE" ]]; then
    ok "Menggunakan image: $IMAGE"
    OS="$(detect_os "$IMAGE")"
    ok "Detected OS: $OS"
    ensure_outdir
    return
  fi
  echo ""
  warn "Tidak ada image disediakan. Pencarian file image di direktori ini & subdirektori..."
  mapfile -t CANDIDATES < <(find "$(pwd)" -maxdepth 3 -type f \( -iname '*.mem' -o -iname '*.raw' -o -iname '*.dmp' -o -iname '*.vmem' -o -iname '*.img' -o -iname '*.bin' \) 2>/dev/null)
  if [[ ${#CANDIDATES[@]} -eq 0 ]]; then
    err "Tidak ada file image ditemukan. Beri path image sebagai argumen: $0 /path/to/image.mem"
    exit 1
  fi
  echo "File image yang ditemukan:"
  local i
  for i in "${!CANDIDATES[@]}"; do
    printf "  [%d] %s\n" "$((i+1))" "${CANDIDATES[$i]}"
  done
  echo ""
  read -rp "Pilih nomor [1-${#CANDIDATES[@]}]: " sel
  if [[ ! "$sel" =~ ^[0-9]+$ || "$sel" -lt 1 || "$sel" -gt ${#CANDIDATES[@]} ]]; then
    err "Pilihan tidak valid."
    exit 1
  fi
  IMAGE="${CANDIDATES[$((sel-1))]}"
  ok "Menggunakan: $IMAGE"
  OS="$(detect_os "$IMAGE")"
  ok "Detected OS: $OS"
  ensure_outdir
}

# Menu utama
main_menu() {
  while true; do
    echo ""
    echo "======================================================================"
    echo -e "  ${STYLE}Volatility 3 - Memory Forensics Toolkit${RESET}"
    echo "======================================================================"
    echo -e "  Image : ${GRN}${IMAGE}${RESET}"
    echo -e "  OS    : ${GRN}${OS}${RESET}"
    echo -e "  Outdir: ${BLU}${OUTDIR}${RESET}"
    echo "----------------------------------------------------------------------"
    echo "  1) Info OS & image              2) Proses (list)"
    echo "  3) Proses (scan/pstree)         4) Command line setiap proses"
    echo "  5) Jaringan (netscan)           6) Jaringan (netstat)"
    echo "  7) File scan                    8) Dump proses memory"
    echo "  9) Dump file (dumpfiles)       10) Registry hive/hashdump"
    echo " 11) Cari string di memory       12) Cari string di dump proses"
    echo " 13) Malware scan (malfind)      14) Driver scan"
    echo " 15) Handles / DLL / VAD         16) Env vars proses"
    echo " 17) Timeliner                   18) Bash history (linux/mac)"
    echo " 19) Plugin lain (manual)        20) Ganti image / OS"
    echo "----------------------------------------------------------------------"
    echo "  L) Toggle save-to-log  |  Q) Keluar"
    echo "----------------------------------------------------------------------"
    read -rp "Pilih menu: " m
    case "$m" in
      1) jalankan_plugin "windows.info.Info";;
      2) menu_proses;;
      3) menu_proses_scan;;
      4) jalankan_plugin "windows.cmdline.CmdLine" "Process command lines";;
      5) jalankan_plugin "windows.netscan.NetScan" "Network connections (scan)";;
      6) jalankan_plugin "windows.netstat.NetStat" "Network connections (netstat)";;
      7) jalankan_plugin "windows.filescan.FileScan";;
      8) dump_proses;;
      9) dump_file;;
      10) menu_registry;;
      11) str_scan_memory;;
      12) str_scan_dump;;
      13) jalankan_plugin "windows.malfind.Malfind";;
      14) jalankan_plugin "windows.driverscan.DriverScan";;
      15) menu_handles;;
      16) jalankan_plugin "windows.envars.Envars";;
      17) jalankan_plugin "timeliner.Timeliner";;
      18) bash_history;;
      19) plugin_manual;;
      20) pick_image;;
      [lL]) toggle_log;;
      [qQ]) exit 0;;
      *) warn "Pilihan tidak dikenal: $m";;
    esac
  done
}

# Toggle simpan log
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

# Cek OS, jika bukan target warn (plugin windows vs linux)
check_os_ok() {
  local need="$1"; local label="$2"
  if [[ "$OS" != "$need" ]]; then
    warn "[$label] biasanya untuk image $need. Lanjut? (y/N)"
    read -r c
    [[ "$c" =~ ^[yY]$ ]] || return 1
  fi
  return 0
}

jalankan_plugin() {
  local p="$1"; shift
  local desc="${*:-$p}"
  check_os_ok "${p%%.*}" "$p" || return
  echo ""
  say "Running: $desc  (tekan [q] untuk kembali)"
  run_vol "$p"
}

run_vol() {
  local p="$1"
  local cmd=( "$VOL" -q -f "$IMAGE" "$p" )
  if [[ "$SAVE_LOG" == "1" && -n "$LOGFILE" ]]; then
    "${cmd[@]}" 2>&1 | tee -a "$LOGFILE" | less -R
  else
    "${cmd[@]}" 2>&1 | less -R
  fi
}

# ----------------------------- MENU PER KATEGORI --------------------------

menu_proses() {
  echo ""
  echo "  Proses (list):"
  echo "    1) pslist       2) psscan       3) pstree"
  echo "    4) psxview      5) sessions"
  read -rp "  Pilih: " s
  case "$s" in
    1) jalankan_plugin "windows.pslist.PsList";;
    2) jalankan_plugin "windows.psscan.PsScan";;
    3) jalankan_plugin "windows.pstree.PsTree";;
    4) jalankan_plugin "windows.psxview.PsXView";;
    5) jalankan_plugin "windows.sessions.Sessions";;
    *) warn "Batal";;
  esac
}

menu_proses_scan() {
  echo ""
  echo "  Proses (scan/pstree):"
  echo "    1) pstree       2) psxview       3) hollowprocesses"
  read -rp "  Pilih: " s
  case "$s" in
    1) jalankan_plugin "windows.pstree.PsTree";;
    2) jalankan_plugin "windows.psxview.PsXView";;
    3) jalankan_plugin "windows.hollowprocesses.HollowProcesses";;
    *) warn "Batal";;
  esac
}

dump_proses() {
  echo ""
  read -rp "  PID proses yang ingin di-dump: " pid
  [[ "$pid" =~ ^[0-9]+$ ]] || { warn "PID invalid"; return; }
  say "Mendump PID $pid ke $OUTDIR ..."
  run_plugin_dump "windows.memmap.Memmap" --pid "$pid" --dump 2>&1 | grep -iE '\.dmp|written' || true
  ls -la "$OUTDIR"/pid.$pid.dmp 2>/dev/null && ok "Dump selesai: $OUTDIR/pid.$pid.dmp"
}

dump_file() {
  echo ""
  read -rp "  Virtual offset file (0x...) atau kosong untuk menu: " off
  if [[ -n "$off" ]]; then
    run_plugin_dump "windows.dumpfiles.DumpFiles" --virtaddr "$off" 2>&1 | grep -iE '\.dat|\.dmp|written' || true
    ok "Lihat file di $OUTDIR"
  else
    echo "  Contoh:"
    echo "    vol -f image windows.filescan | grep -i suspicious"
    echo "    (salin offset, lalu dump lewat menu ini)"
    run_plugin "windows.filescan.FileScan"
  fi
}

menu_registry() {
  echo ""
  echo "  Registry:"
  echo "    1) hivelist      2) printkey       3) hashdump"
  echo "    4) userassist    5) scheduled tasks"
  read -rp "  Pilih: " s
  case "$s" in
    1) jalankan_plugin "windows.registry.hivelist.HiveList";;
    2) jalankan_plugin "windows.registry.printkey.PrintKey";;
    3) jalankan_plugin "windows.registry.hashdump.Hashdump";;
    4) jalankan_plugin "windows.registry.userassist.UserAssist";;
    5) jalankan_plugin "windows.registry.scheduled_tasks.ScheduledTasks";;
    *) warn "Batal";;
  esac
}

menu_handles() {
  echo ""
  echo "  1) DllList   2) Handles   3) VadInfo   4) LdrModules"
  read -rp "  Pilih: " s
  case "$s" in
    1) jalankan_plugin "windows.dlllist.DllList";;
    2) jalankan_plugin "windows.handles.Handles";;
    3) jalankan_plugin "windows.vadinfo.VadInfo";;
    4) jalankan_plugin "windows.ldrmodules.LdrModules";;
    *) warn "Batal";;
  esac
}

bash_history() {
  if [[ "$OS" == "windows" ]]; then
    warn "Bash history biasanya untuk image Linux/macOS."
  fi
  jalankan_plugin "linux.bash.Bash"
}

plugin_manual() {
  echo ""
  echo "  Daftar plugin Windows yang berguna:"
  echo "   windows.mftscan.MFTScan | windows.svcscan.SvcScan | windows.cmdscan.CmdScan"
  echo "   windows.consoles.Consoles | windows.mutantscan.MutantScan | windows.symlinkscan.SymlinkScan"
  echo "   windows.modscan.ModScan | windows.callbacks.Callbacks | windows.ssdt.SSDT"
  echo "   windows.yarascan / vadregexscan / vadyarascan"
  echo ""
  read -rp "  Ketik full plugin path (mis. windows.ssdt.SSDT): " p
  [[ -n "$p" ]] && jalankan_plugin "$p"
}

str_scan_memory() {
  echo ""
  read -rp "  Regex / string yang dicari (mis. flag|http|password): " pat
  [[ -z "$pat" ]] && { warn "Batal"; return; }
  read -rp "  Gunakan yarascan (y/N)? " use_y
  if [[ "$use_y" =~ ^[yY]$ ]]; then
    run_plugin "windows.vadyarascan.VadYaraScan" --yara-string "$pat"
  else
    out="$OUTDIR/strings_mem.txt"
    say "strings pada image -> $out"
    strings -n 6 "$IMAGE" > "$out"
    grep -inE "$pat" "$out" | head -200
    ok "Full strings: $out"
  fi
}

str_scan_dump() {
  echo ""
  read -rp "  PATH file dump proses (dari /tmp/vol_result/...): " df
  [[ -f "$df" ]] || { err "File tidak ditemukan: $df"; return; }
  read -rp "  Regex / string: " pat
  [[ -z "$pat" ]] && { warn "Batal"; return; }
  strings -n 5 "$df" | grep -inE "$pat" | head -200
}

# ----------------------------- MAIN ---------------------------------------

init "$@"
pick_image
main_menu
