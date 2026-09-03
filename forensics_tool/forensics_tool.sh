#!/usr/bin/env bash
# =============================================================================
#  Forensics Disk Toolkit
#  --------------------------------------------------------------------------
#  Tools bantu forensics untuk mengekstrak / menganalisa file image disk
#  (disk dump .img/.dd/.raw, E01/EWF, virtual disk vmdk/vdi/vhd/qcow2,
#  dan arsip/iso). Bekerja otomatis: deteksi tipe -> mount / extract ->
#  salin file penting -> unmount beres.
#
#  Fitur:
#   [AUTO]  - deteksi tipe image, list partisi, mount ke /mnt/<nama>
#             (read-only), salin file penting ke folder hasil, lalu
#             auto-unmount. Kalau mount butuh sudo gagal, fallback ke
#             extract user-space (7z / binwalk / fuse).
#   [MOUNT] - mount satu image ke /mnt/<nama> (manual).
#   [EXTR]  - extract / salin file dari image (auto coba mount dulu).
#   [CARVE] - carve file tersembunyi pakai binwalk (fallback).
#   [INFO]  - ringkasan image: tipe, ukuran, partisi, filesystem.
#   [UNMT]  - unmount semua yang lagi ke-mount + lepas loop device.
#
#  Cara pakai:
#     ./forensics_tool.sh                         -> menu interaktif
#     ./forensics_tool.sh <file-image>            -> analisis + extract otomatis
#     ./forensics_tool.sh info <file>
#     ./forensics_tool.sh detect <file>
#     ./forensics_tool.sh mount <file>            -> mount ke /mnt/<nama>
#     ./forensics_tool.sh extract <file>          -> mount/extract + salin
#     ./forensics_tool.sh carve <file>
#     ./forensics_tool.sh unmount                 -> unmount semua
#
#  Hasil tersimpan di: <direktori tempat tool dijalankan>/forensics_result/
#  Mount point di     : /mnt/<nama_image>/
#
#  Requirement: file, 7z/7za, mount, losetup, fdisk/partx, binwalk (opsional)
#  (opsional: ewfmount, qemu-nbd untuk tipe E01/disk virtual tertentu)
# =============================================================================

set -uo pipefail

# ----------------------------- KONFIGURASI --------------------------------
OUTDIR_BASE="$(pwd)/forensics_result"  # hasil di folder tempat tool dijalankan
MOUNT_BASE="/mnt"                      # tempat mount image (sesuai permintaan)
STYLE="\e[1;36m"; RESET="\e[0m"
RED="\e[1;31m"; GRN="\e[1;32m"; YLW="\e[1;33m"; BLU="\e[1;34m"; MGT="\e[1;35m"; ORG="\e[1;33m"

IMAGE=""
OUTDIR=""
OUTDIR_IMG=""
MOUNT_POINT=""
LOOPS=()          # daftar loop device yang dipakai (untuk dibersihkan)
MOUNTED=()        # daftar mount point aktif

# ----------------------------- UTILITAS -----------------------------------
say()  { echo -e "${STYLE}[*]${RESET} $*"; }
ok()   { echo -e "${GRN}[+]${RESET} $*"; }
warn() { echo -e "${YLW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[-]${RESET} $*"; }
info() { echo -e "${BLU}[i]${RESET} $*"; }

has() { command -v "$1" >/dev/null 2>&1; }

resolve() {
  local p="$1"
  if [[ "$p" != /* ]]; then p="$(pwd)/$p"; fi
  echo "$p"
}

slug() { basename "$1" | sed -E 's/[^A-Za-z0-9._-]+/_/g'; }

# ----------------------- DETEKSI TIPE IMAGE --------------------------------
# Klasifikasi image: raw-disk | ewf | vmdk | vdi | vhd | qcow2 | iso | archive
detect_image_type() {
  local img="$1"
  local sig ext
  sig=$(file -b "$img" 2>/dev/null)
  ext="${img##*.}"; ext="${ext,,}"

  case "$sig" in
    *"gzip compressed data"*|*"Zip archive"*|*"tar archive"*|*"bzip2"*|*"xz compressed"*|*"7-zip archive"*)
      echo "archive"; return;;
    *"QEMU QCOW"*) echo "qcow2"; return;;
    *"VirtualBox Disk Image"*|*"VDI"*) echo "vdi"; return;;
    *"VMware"*|*"VMDK"*) echo "vmdk"; return;;
    *"Virtual Hard Disk"*|*"VHD"*) echo "vhd"; return;;
    *"E01"*|*"EnCase"*|*"EWF"*) echo "ewf"; return;;
    *"ISO 9660"*|*"isofs"*|*"UDF filesystem"*) echo "iso"; return;;
    *"DOS/MBR boot sector"*|*"DOS/MBR"*|*"x86 boot sector"*|*"GPT"*|*"Microsoft Disk Image"*|*"ext2 filesystem"*|*"ext3 filesystem"*|*"ext4 filesystem"*|*"Linux rev 1.0 ext"*)
      echo "raw-disk"; return;;
  esac
  # fallback: ekstensi
  case "$ext" in
    e01|e02|lf01|ewf) echo "ewf";;
    vmdk) echo "vmdk";;
    vdi)  echo "vdi";;
    vhd)  echo "vhd";;
    qcow2|qcow) echo "qcow2";;
    iso)  echo "iso";;
    img|dd|raw|bin) echo "raw-disk";;
    docx|xlsx|pptx|zip|jar|apk|7z|gz|bz2|xz|tar) echo "archive";;
    *) echo "unknown";;
  esac
}

# ----------------------- LIST PARTISI (raw disk) ---------------------------
list_partitions() {
  local img="$1"
  info "Label partisi (fdisk):"
  fdisk -l "$img" 2>/dev/null | grep -E '^/dev|^Device|Disk ' | head -30
  echo ""
  info "Partisi terdeteksi (partx):"
  if has partx; then
    partx -s -o NR,START,END,SECTORS,TYPE "$img" 2>/dev/null | head -20 || warn "tidak bisa baca partisi (perlu root?)"
  fi
}

# ----------------------- SETUP LOOP + MOUNT --------------------------------
# Setup loop device untuk raw image supaya bisa di-mount per partisi.
# Butuh root; mengembalikan daftar loop yang terpasang (di $LOOPS).
setup_loops() {
  local img="$1"
  LOOPS=()
  if ! has losetup; then warn "losetup tidak ada"; return 1; fi
  if ! sudo -n true 2>/dev/null; then warn "butuh sudo (password) untuk setup loop"; fi
  # attach image ke loop device scan
  sudo losetup -P -f "$img" 2>/dev/null || { warn "gagal attach loop"; return 1; }
  # cari loop terbaru
  local loop
  loop=$(sudo losetup -j "$img" 2>/dev/null | head -1 | cut -d: -f1)
  if [[ -z "$loop" ]]; then warn "loop device tidak terdeteksi"; return 1; fi
  LOOPS+=("$loop")
  ok "Loop: $loop"
  # partisi loop : sudo losetup -P otomatis bikin /dev/loopXpN
  sudo partx -a "$loop" 2>/dev/null || true
}

# mount_single <device-or-mountsrc> <mountpoint>: try sudo mount ro, fallback
mount_ro_src() {
  local src="$1" mp="$2"
  sudo mkdir -p "$mp" 2>/dev/null
  if sudo mount -o ro "$src" "$mp" 2>/dev/null; then
    MOUNTED+=("$mp")
    return 0
  fi
  warn "mount '$src' gagal (butuh root / FS tidak didukung) - coba fallback..."
  return 1
}

# ----------------------- EXTRACT USER-SPACE (tanpa root) ------------------
# 7z bisa bongkar banyak FS (ext/ntfs/fat) + arsip. Dipakai sebagai fallback.
extract_7z() {
  local src="$1" dst="$2"
  if ! has 7z; then warn "7z tidak ada, lewati"; return 1; fi
  mkdir -p "$dst"
  info "Mencoba extract user-space 7z dari '$src' -> $dst"
  if 7z x -o"$dst" -y "$src" >/dev/null 2>&1; then
    ok "7z extract berhasil: $dst"
    return 0
  fi
  warn "7z gagal membuka '$src'"
  return 1
}

# ----------------------- MOUNT POINT & EXTRACT -----------------------------
# Vorbereitung folder hasil per image
prep_outdir() {
  local img="$1"
  OUTDIR_IMG="$OUTDIR_BASE/$(slug "$img")"
  mkdir -p "$OUTDIR_IMG" 2>/dev/null
}

# extract dari sebuah sumber (mountpoint/device/file) -> salin file penting
extract_from() {
  local src="$1" partlabel="$2"
  [[ -d "$src" ]] || { warn "sumber bukan folder: $src"; return 1; }
  local dst="$OUTDIR_IMG/$partlabel"
  mkdir -p "$dst"
  info "Menyalin file dari '$src' -> $dst"
  # salin file regular yang bisa dibaca, pertahanin struktur
  cp -a "$src"/. "$dst"/ 2>/dev/null || true
  local n
  n=$(find "$dst" -type f 2>/dev/null | wc -l)
  ok "Tersalin $n file ke $dst"
}

# ---------------- ALUR UTAMA: ANALISIS + EXTRACT OTOMATIS ------------------
# bagan: detect -> outdir -> mount/extract -> copy -> unmount (auto)
run_full() {
  local img
  img="$(resolve "$1")"
  [[ -f "$img" ]] || { err "Image tidak ditemukan: $1"; return 1; }
  IMAGE="$img"
  OUTDIR="$OUTDIR_BASE"
  mkdir -p "$OUTDIR"
  prep_outdir "$img"

  echo ""; say "Image: $img"
  local typ
  typ=$(detect_image_type "$img")
  info "Tipe terdeteksi: ${MGT}$typ${RESET} ($(file -b "$img"))"

  case "$typ" in
    raw-disk)
      list_partitions "$img"
      # coba mount loop (perlu root)
      if setup_loops "$img"; then
        local lp="${LOOPS[0]}"
        local i=0
        for d in "${lp}"p*; do
          [[ -e "$d" ]] || continue
          i=$((i+1))
          local mp="$MOUNT_BASE/$(slug "$img")_p$i"
          if mount_ro_src "$d" "$mp"; then
            extract_from "$mp" "part$i"
            # biar file bisa dibaca tanpa tetap mount, kita blm unmount dulu
          fi
        done
      fi
      # kalau tidak ada mount sama sekali, fallback extract 7z per partisi/raw
      if [[ ${#MOUNTED[@]} -eq 0 ]]; then
        warn "Mount gagal - fallback extract user-space pada image penuh"
        extract_7z "$img" "$OUTDIR_IMG/7z_raw"
      fi
      ;;
    iso|archive)
      extract_7z "$img" "$OUTDIR_IMG/extracted"
      ;;
    vmdk|vdi|vhd|qcow2)
      # virtual disk: coba 7z dulu (bisa bongkar isi), fallback binwalk
      extract_7z "$img" "$OUTDIR_IMG/extracted" || carve_binwalk "$img" "$OUTDIR_IMG/carved"
      ;;
    ewf)
      if has ewfmount; then
        local ewfmp="$MOUNT_BASE/$(slug "$img")_ewf"
        sudo mkdir -p "$ewfmp" 2>/dev/null
        if ewfmount "$img" "$ewfmp" 2>/dev/null; then
          MOUNTED+=("$ewfmp")
          extract_from "$ewfmp" "ewf"
          ewfunmount "$ewfmp" 2>/dev/null
        else
          warn "ewfmount gagal"
        fi
      else
        warn "ewfmount tidak ada - coba 7z / carving fallback"
        extract_7z "$img" "$OUTDIR_IMG/extracted" || carve_binwalk "$img" "$OUTDIR_IMG/carved"
      fi
      ;;
    unknown|*)
      warn "Tipe tidak dikenal - coba 7z lalu binwalk carving"
      extract_7z "$img" "$OUTDIR_IMG/extracted" || carve_binwalk "$img" "$OUTDIR_IMG/carved"
      ;;
  esac

  echo ""
  ok "Selesai. Hasil di: ${BLU}$OUTDIR_IMG${RESET}"
  echo ""
  auto_unmount
}

# ----------------------- CARVING (BINWALK) ---------------------------------
carve_binwalk() {
  local img="$1" dst="$2"
  if ! has binwalk; then warn "binwalk tidak ada - lewati carving"; return 1; fi
  mkdir -p "$dst"
  info "Carving pakai binwalk -> $dst"
  binwalk -M -e -C "$dst" "$img" >/dev/null 2>&1 || true
  ok "Carving selesai: $dst"
}

# ----------------------- AUTO-UNMOUNT --------------------------------------
auto_unmount() {
  local did=0
  # unmount mount point yang kita buka
  for mp in "${MOUNTED[@]}"; do
    if mountpoint -q "$mp" 2>/dev/null || mount | grep -q " $mp "; then
      sudo umount "$mp" 2>/dev/null && { ok "Unmount: $mp"; did=1; } || warn "gagal unmount $mp"
    fi
  done
  # lepas loop device
  for lp in "${LOOPS[@]}"; do
    sudo losetup -d "$lp" 2>/dev/null && { ok "Lepas loop: $lp"; did=1; }
  done
  if [[ $did -eq 1 || ${#LOOPS[@]} -gt 0 || ${#MOUNTED[@]} -gt 0 ]]; then
    ok "Auto-unmount selesai."
  else
    info "Tidak ada yang perlu di-unmount."
  fi
  LOOPS=(); MOUNTED=()
}

# unmount semua (dipanggil user lewat command/menu) - lebih agresif
unmount_all() {
  info "Mencari mount point yang aktif di $MOUNT_BASE ..."
  local mp
  while read -r mp; do
    [[ -n "$mp" ]] || continue
    sudo umount "$mp" 2>/dev/null && ok "Unmount: $mp"
  done < <(mount | grep "$MOUNT_BASE" | awk '{print $3}')
  info "Lepas semua loop device yang dipakai tool ini ..."
  local lp
  while read -r lp; do
    [[ -n "$lp" ]] || continue
    sudo losetup -d "$lp" 2>/dev/null && ok "Lepas loop: $lp"
  done < <(losetup -a 2>/dev/null | grep -i "forensics\|$(basename "$IMAGE" 2>/dev/null)" | cut -d: -f1 | sort -u)
}

# ------------------------------- COMMANDS ----------------------------------
cmd_info() {
  [[ -n "$IMAGE" ]] || { err "Belum ada image. Gunakan 'set <file>' atau argumen file."; return 1; }
  echo ""; say "Info image: $IMAGE"
  echo ""
  echo -e "${STYLE}== Tipe ==${RESET}"; file -b "$IMAGE"
  echo -e "${STYLE}== Ukuran ==${RESET}"; ls -lh "$IMAGE" | awk '{print $5, $9}'
  echo ""
  local typ; typ=$(detect_image_type "$IMAGE")
  echo -e "${STYLE}== Klasifikasi: ${MGT}$typ${RESET} ==${RESET}"
  case "$typ" in raw-disk) list_partitions "$IMAGE";; esac
}

cmd_detect() {
  [[ -n "$IMAGE" ]] || { err "Belum ada image."; return 1; }
  local typ; typ=$(detect_image_type "$IMAGE")
  say "Image: $IMAGE"
  ok "Tipe: $typ"
  file -b "$IMAGE"
}

cmd_mount() {
  [[ -n "$IMAGE" ]] || { err "Belum ada image."; return 1; }
  local name mp
  prep_outdir "$IMAGE"
  name="$(slug "$IMAGE")"; mp="$MOUNT_BASE/$name"
  say "Mount '$IMAGE' ke $mp (read-only)"
  case "$(detect_image_type "$IMAGE")" in
    raw-disk)
      if setup_loops "$IMAGE"; then
        local lp="${LOOPS[0]}"; local i=0
        for d in "${lp}"p*; do
          [[ -e "$d" ]] || continue
          i=$((i+1)); local m="${mp}_p$i"
          mount_ro_src "$d" "$m" && ok "Tersedia di $m"
        done
      else
        warn "Perlu sudo mount langsung:"
        sudo mkdir -p "$mp" 2>/dev/null
        sudo mount -o ro,loop "$IMAGE" "$mp" 2>/dev/null && ok "Tersedia di $mp" || err "gagal mount"
      fi
      ;;
    *)
      warn "Tipe ini tidak didukung mount langsung - gunakan 'extract' untuk fallback:"
      extract_7z "$IMAGE" "$OUTDIR_IMG/extracted" 2>/dev/null || true
      ;;
  esac
}

cmd_extract() {
  run_full "$IMAGE"
}

cmd_carve() {
  [[ -n "$IMAGE" ]] || { err "Belum ada image."; return 1; }
  prep_outdir "$IMAGE"
  carve_binwalk "$IMAGE" "$OUTDIR_IMG/carved"
  ok "Hasil carving: $OUTDIR_IMG/carved"
}

cmd_set() {
  IMAGE="$(resolve "$1")"
  [[ -f "$IMAGE" ]] && ok "Image di-set: $IMAGE" || { err "File $1 tidak ditemukan"; IMAGE=""; }
}

# ------------------------------- MENU --------------------------------------
main_menu() {
  while true; do
    echo ""
    echo "======================================================================"
    echo -e "  ${STYLE}Forensics Disk Toolkit${RESET}"
    echo "======================================================================"
    if [[ -n "$IMAGE" ]]; then
      echo -e "  Image : ${GRN}$IMAGE${RESET}  ($(detect_image_type "$IMAGE"))"
    else
      echo -e "  Image : ${YLW}(belum dipilih)${RESET}"
    fi
    echo -e "  Output: ${BLU}$OUTDIR_BASE${RESET}   Mount: ${BLU}$MOUNT_BASE${RESET}"
    echo "----------------------------------------------------------------------"
    echo -e "  ${STYLE}[INFO]${RESET}  1) Info image          2) Deteksi tipe"
    echo -e "         3) Set image file"
    echo -e "  ${STYLE}[AKSI]${RESET} 4) Mount ke /mnt      5) Extract otomatis"
    echo -e "         6) Carve (binwalk)"
    echo -e "  ${STYLE}[BERSIH]${RESET}7) Unmount semua"
    echo "----------------------------------------------------------------------"
    echo -e "  S) Set image   U) Unmount   Q) Keluar"
    echo "----------------------------------------------------------------------"
    read -rp "  Pilih [1-7/S/U/Q]: " m
    case "$m" in
      1) cmd_info;;
      2) cmd_detect;;
      3) read -rp "  Path image: " p; [[ -n "$p" ]] && cmd_set "$p";;
      4) cmd_mount;;
      5) cmd_extract;;
      6) cmd_carve;;
      7) unmount_all;;
      [sS]) read -rp "  Path image: " p; [[ -n "$p" ]] && cmd_set "$p";;
      [uU]) unmount_all;;
      [qQ]) echo "  Sampai jumpa."; break;;
      *) warn "Pilihan tidak dikenal: $m";;
    esac
  done
}

# ------------------------------ DISPATCH -----------------------------------
usage() {
  echo ""
  echo "Cara pakai:"
  echo "  $0                                   -> menu interaktif"
  echo "  $0 <file-image>                      -> analisis + extract otomatis"
  echo "  $0 info <file>"
  echo "  $0 detect <file>"
  echo "  $0 mount <file>                      -> mount ke /mnt/<nama>"
  echo "  $0 extract <file>                    -> mount/extract + salin file"
  echo "  $0 carve <file>"
  echo "  $0 unmount                           -> unmount semua + lepas loop"
  echo ""
  echo "Hasil  : $OUTDIR_BASE/  (folder tempat tool dijalankan)"
  echo "Mount  : $MOUNT_BASE/"
}

main() {
  # --- bentuk 1: $0 <cmd> <file>  (detect/extract/mount/carve/info) ---
  if [[ $# -ge 1 ]]; then
    case "$1" in
      -h|--help|help) usage; exit 0;;
      unmount) unmount_all; exit 0;;
      detect|info|mount|extract|carve|set)
        local c="$1"; local f="${2:-}"
        if [[ -n "$f" && -f "$(resolve "$f")" ]]; then
          IMAGE="$(resolve "$f")"
          case "$c" in
            detect)  cmd_detect;;
            info)    cmd_info;;
            mount)   cmd_mount;;
            extract) cmd_extract;;
            carve)   cmd_carve;;
            set)     cmd_set "$f";;
          esac
        else
          err "File image tidak ditemukan: $f"
          usage; exit 1
        fi
        exit 0;;
    esac
  fi

  # --- bentuk 2: $0 <file>  atau  $0 <file> <cmd> ---
  if [[ $# -ge 1 && -f "$1" ]]; then
    IMAGE="$(resolve "$1")"
    if [[ $# -eq 1 ]]; then
      run_full "$IMAGE"; exit 0
    fi
    case "$2" in
      mount)   cmd_mount;;
      extract) cmd_extract;;
      carve)   cmd_carve;;
      info)    cmd_info;;
      detect)  cmd_detect;;
      *) err "Sub-perintah '$2' tidak dikenal"; usage; exit 1;;
    esac
    exit 0
  fi

  # --- tidak ada file & bukan cmd -> menu ---
  if [[ $# -ge 1 ]]; then
    err "Usage: $0 [file] | <cmd> <file> | -h"
    exit 1
  fi
  main_menu
}

main "$@"
