#!/usr/bin/env bash
# =============================================================================
#  TShark - Interactive Network Forensics Toolkit
#  --------------------------------------------------------------------------
#  Fitur:
#   - Auto-pilih pcap (argumen atau cari di direktori)
#   - Ringkasan capture & protocol hierarchy
#   - Konversasi / endpoints / HTTP / DNS / credentials
#   - Follow TCP stream, export objects, filter & hexdump paket
#   - Simpan output ke log dengan timestamp
#
#  Cara pakai:
#     ./tshark_menu.sh                          -> interaktif (pilih file)
#     ./tshark_menu.sh /path/capture.pcap       -> langsung pakai file tsb
#
#  Requirement: tshark (Wireshark) sudah ada di PATH
# =============================================================================

set -uo pipefail

TSHARK="tshark"
LOGDIR_BASE="/tmp/tshark_forensics"

STYLE="\e[1;36m"; RESET="\e[0m"
RED="\e[1;31m"; GRN="\e[1;32m"; YLW="\e[1;33m"; BLU="\e[1;34m"

say()  { echo -e "${STYLE}[*]${RESET} $*"; }
ok()   { echo -e "${GRN}[+]${RESET} $*"; }
warn() { echo -e "${YLW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[-]${RESET} $*"; }

resolve() {
  local p="$1"
  if [[ "$p" != /* ]]; then p="$(pwd)/$p"; fi
  echo "$p"
}

PCAP=""
SAVE_LOG=0
LOGFILE=""
EXPORT_DIR="$LOGDIR_BASE/export_$$"

ensure_dirs() {
  mkdir -p "$EXPORT_DIR" 2>/dev/null
}

# run_tshark <args...> -> eksekusi tshark dari PCAP, dgn opsi log opsional
run_tshark() {
  echo ""
  say "Command: $TSHARK -r $PCAP $*"
  if [[ "$SAVE_LOG" == "1" && -n "$LOGFILE" ]]; then
    "$TSHARK" -r "$PCAP" "$@" 2>&1 | tee -a "$LOGFILE"
  else
    "$TSHARK" -r "$PCAP" "$@" 2>&1
  fi
  echo ""
}

# capaian dasar
summary()      { run_tshark -q -z io,phs; }
proto_detail() { run_tshark -q -z http,tree; }

conv_menu() {
  echo "  Konversasi:"
  echo "    1) TCP    2) UDP    3) IP    4) HTTP"
  read -rp "  Pilih: " s
  case "$s" in
    1) run_tshark -q -z conv,tcp;;
    2) run_tshark -q -z conv,udp;;
    3) run_tshark -q -z conv,ip;;
    4) run_tshark -q -z conv,http;;
    *) warn "Batal";;
  esac
}

endpoints_menu() {
  echo "  Endpoints:"
  echo "    1) TCP    2) UDP    3) IP"
  read -rp "  Pilih: " s
  case "$s" in
    1) run_tshark -q -z endpoints,tcp;;
    2) run_tshark -q -z endpoints,udp;;
    3) run_tshark -q -z endpoints,ip;;
    *) warn "Batal";;
  esac
}

http_req() {
  run_tshark -Y "http.request" -T fields \
    -e frame.number -e ip.src -e http.request.method -e http.host -e http.request.uri \
    -E header=y -E separator=" | "
}

dns_queries() {
  run_tshark -Y "dns" -T fields \
    -e frame.number -e ip.src -e dns.qry.name -e dns.qry.type -e dns.a \
    -E header=y -E separator=" | "
}

credentials() { run_tshark -q -z credentials; }

follow_stream() {
  echo ""
  # daftar stream TCP yang ada
  echo "  Stream TCP yang ditemukan:"
  tcp_streams=$(tshark -r "$PCAP" -T fields -e tcp.stream 2>/dev/null | sort -nu | tr '\n' ' ')
  echo "    $tcp_streams"
  read -rp "  Nomor stream yang ingin di-follow: " n
  [[ -z "$n" ]] && { warn "Batal"; return; }
  read -rp "  Mode (ascii/raw/hex)? [ascii]: " mode
  mode="${mode:-ascii}"
  case "$mode" in
    raw)    run_tshark -q -z "follow,tcp,raw,$n";;
    hex)    run_tshark -q -z "follow,tcp,hex,$n";;
    *)      run_tshark -q -z "follow,tcp,ascii,$n";;
  esac
}

export_objects() {
  echo ""
  echo "  Export objects:"
  echo "    1) HTTP    2) SMB    3) TFTP    4) IMF    5) SMTP"
  read -rp "  Pilih: " s
  proto="http"
  case "$s" in
    1) proto="http";;
    2) proto="smb";;
    3) proto="tftp";;
    4) proto="imf";;
    5) proto="smtp";;
    *) warn "Batal"; return;;
  esac
  ensure_dirs
  say "Export $proto objects -> $EXPORT_DIR"
  tshark -r "$PCAP" --export-objects "$proto,$EXPORT_DIR" 2>&1 | head -3
  ls -la "$EXPORT_DIR" 2>/dev/null
}

filter_pkt() {
  echo ""
  read -rp "  Display filter (mis. http || dns || tcp.port==80): " f
  [[ -z "$f" ]] && { warn "Batal"; return; }
  run_tshark -Y "$f" -E header=y
}

hexdump_pkt() {
  echo ""
  read -rp "  Nomor packet yang ingin di-hexdump: " n
  [[ -z "$n" ]] && { warn "Batal"; return; }
  run_tshark -Y "frame.number==$n" -x
}

detail_pkt() {
  echo ""
  read -rp "  Nomor packet untuk lihat detail (-V): " n
  [[ -z "$n" ]] && { warn "Batal"; return; }
  run_tshark -Y "frame.number==$n" -V
}

list_pkts() {
  read -rp "  Tampilkan berapa paket pertama? [50]: " n
  n="${n:-50}"
  run_tshark -c "$n" -E header=y
}

toggle_log() {
  if [[ "$SAVE_LOG" == "1" ]]; then
    SAVE_LOG=0
    warn "Save-to-log dimatikan."
  else
    SAVE_LOG=1
    LOGFILE="$LOGDIR_BASE/tshark_log_$(date +%Y%m%d_%H%M%S).txt"
    mkdir -p "$LOGDIR_BASE"
    ok "Log akan disimpan ke: $LOGFILE"
  fi
}

pick_pcap() {
  if [[ -n "$PCAP" ]]; then
    ok "Menggunakan capture: $PCAP"
    return
  fi
  warn "Tidak ada pcap disediakan. Pencarian file capture di direktori ini & subdirektori..."
  mapfile -t CANDIDATES < <(find "$(pwd)" -maxdepth 3 -type f \( -iname '*.pcap' -o -iname '*.pcapng' -o -iname '*.cap' \) 2>/dev/null)
  if [[ ${#CANDIDATES[@]} -eq 0 ]]; then
    err "Tidak ada file capture ditemukan. Beri path pcap sebagai argumen: $0 /path/capture.pcap"
    exit 1
  fi
  echo "File capture ditemukan:"
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
  PCAP="${CANDIDATES[$((sel-1))]}"
  ok "Menggunakan: $PCAP"
}

main_menu() {
  while true; do
    echo ""
    echo "======================================================================"
    echo -e "  ${STYLE}TShark - Network Forensics Toolkit${RESET}"
    echo "======================================================================"
    echo -e "  Capture : ${GRN}${PCAP}${RESET}"
    echo -e "  Export  : ${BLU}${EXPORT_DIR}${RESET}"
    echo "----------------------------------------------------------------------"
    echo "  1) Ringkasan (io,phs)         2) Protocol tree (http)"
    echo "  3) Konversasi                 4) Endpoints"
    echo "  5) HTTP request               6) DNS query"
    echo "  7) Credentials                8) Follow TCP stream"
    echo "  9) Export objects            10) List paket (awal)"
    echo " 11) Filter paket              12) Hexdump paket"
    echo " 13) Detail paket (-V)         14) Ganti capture"
    echo "----------------------------------------------------------------------"
    echo "  L) Toggle save-to-log  |  Q) Keluar"
    echo "----------------------------------------------------------------------"
    read -rp "Pilih menu: " m
    case "$m" in
      1) summary;;
      2) proto_detail;;
      3) conv_menu;;
      4) endpoints_menu;;
      5) http_req;;
      6) dns_queries;;
      7) credentials;;
      8) follow_stream;;
      9) export_objects;;
      10) list_pkts;;
      11) filter_pkt;;
      12) hexdump_pkt;;
      13) detail_pkt;;
      14) PCAP=""; pick_pcap;;
      [lL]) toggle_log;;
      [qQ]) exit 0;;
      *) warn "Pilihan tidak dikenal: $m";;
    esac
  done
}

# ----------------------------- MAIN ---------------------------------------

if ! command -v "$TSHARK" >/dev/null 2>&1; then
  err "tshark tidak ditemukan di PATH. Install: sudo apt install tshark"
  exit 1
fi

if [[ $# -ge 1 && -f "$1" ]]; then
  PCAP="$(resolve "$1")"
  shift
  if [[ $# -ge 1 ]]; then
    # mode direct: jalankan opsi tshark langsung
    run_tshark "$@"
    exit 0
  fi
fi

pick_pcap
main_menu
