#!/usr/bin/env bash
# =============================================================================
#  Reverse Engineering Toolkit (RE Toolkit)
#  --------------------------------------------------------------------------
#  Membantu "membaca" binary / file executable sehingga output objdump,
#  readelf, rabin2, strings, gdb jadi lebih mudah dimengerti.
#
#  Fitur:
#   [INFO]    - info file: tipe binary, arsitektur, protections (NX/PIE/RELRO/
#              Canary), stripped atau tidak, bahasa compile dll.
#   [STRINGS] - cari string: flag (auto KTCG/flag/CTF/{}), cari kata bebas,
#              string per-section, string dengan offset, escape non-print.
#   [SECTION] - daftar section (readelf -S) + cari section tertentu.
#   [DISASM]  - list fungsi (nm) + disasembel fungsi tertentu (objdump -dr),
#              cari referensi / alamat, cari string yang dipakai fungsi.
#   [DATA]    - dump isi section (.rodata/.data/.bss) + hexdump, ekstrak
#              data tersembunyi (hidden string / blobs).
#   [CRYPTO]  - XOR bruteforce single-byte, cari key/flag tersembunyi,
#              deteksi string ter-encode (base64/hex/binary) di dalam binary,
#              cari pola key & IV.
#   [DYN]     - jalankan program + ltrace/strace (lihat call library),
#              bongkar pakai radare2/rabin2, cari fungsi main dengan gdb/objdump.
#
#  Cara pakai:
#     ./re_tool.sh                          -> menu interaktif
#     ./re_tool.sh <file>                   -> analisis cepat (info + strings flag)
#     ./re_tool.sh info <file>
#     ./re_tool.sh strings <file> [pola]
#     ./re_tool.sh section <file> [nama]
#     ./re_tool.sh disasm <file> [fungsi|alamat]
#     ./re_tool.sh data <file> [.rodata|.data|...]
#     ./re_tool.sh crypto <file>
#     ./re_tool.sh xor <file>
#     ./re_tool.sh run <file> [args...]
#
#  Requirement: file, readelf, objdump, strings, xxd, nm, python3
#  (opsional: rabin2/radare2, gdb, ltrace, strace)
#
#  FLAG PREFIX (opsional - prefix flag anda sendiri):
#     ./re_tool.sh --prefix "KTCG,CTF,MyCTF,{}" <file>
#     export FLAGPREFIX="KTCG,CTF,{}"             (lingkungan)
#     echo "FLAGPREFIX=KTCG,CTF,{}" > .re_tool.conf   (file config lokal)
#     Default pakai: KTCG,flag,FLAG,ctf,CTF,secret,{}
#     Semua pemindai flag (flag / strings / hidden / autodecode) memakai daftar ini.
# =============================================================================

set -uo pipefail

# ----------------------------- KONFIGURASI --------------------------------
PY="python3"
FILEB="file"
READELF="readelf"
OBJDUMP="objdump"
STRINGS="strings"
XXD="xxd"
NM="nm"
STYLE="\e[1;36m"; RESET="\e[0m"
RED="\e[1;31m"; GRN="\e[1;32m"; YLW="\e[1;33m"; BLU="\e[1;34m"; MGT="\e[1;35m"; ORG="\e[1;33m"

TARGET=""

# --- Flag prefix (dapat diset via --prefix / env FLAGPREFIX / file .re_tool.conf)
# Urutan prioritas: CLI --prefix > env FLAGPREFIX > file conf > default
load_flag_prefix() {
  local conf=".re_tool.conf"
  if [[ -n "${CLI_PREFIX:-}" ]]; then
    FLAGPREFIX="$CLI_PREFIX"
  elif [[ -n "${FLAGPREFIX:-}" ]]; then
    : # sudah dari env
  elif [[ -f "$conf" ]]; then
    local val
    val=$(grep -E '^FLAGPREFIX=' "$conf" 2>/dev/null | head -1 | cut -d= -f2-)
    FLAGPREFIX="${val:-KTCG,flag,FLAG,ctf,CTF,secret,{}"
  else
    FLAGPREFIX="KTCG,flag,FLAG,ctf,CTF,secret,{}"
  fi
  # bangun regex untuk pencarian (escape meta-character, gabung dengan |)
  build_flag_regex
}

# build_flag_regex: jadikan FLAGPREFIX -> regex OR untuk grep -aiE / python re
build_flag_regex() {
  local IFS=','
  local out=""
  for p in $FLAGPREFIX; do
    [[ -z "$p" ]] && continue
    local esc="${p//\//\\/}"
    # escape karakter regex khusus
    esc=$(printf '%s' "$esc" | sed -e 's/[.[\*^$()+?{|]/\\&/g')
    out="$out${out:+|}$esc"
  done
  [[ -z "$out" ]] && out="KTCG|flag|FLAG|ctf|CTF|secret"
  FLAGREGEX="$out"
}

# flag_matches <string>: 0 kalau string memuat pola flag yang dikonfigurasi
flag_matches() {
  printf '%s\n' "$1" | grep -qaiE "$FLAGREGEX"
}

# flaghl: highlight baris yang match pola flag (output berwarna hijau + [F])
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

need_check() {
  local missing=()
  for b in file readelf objdump strings xxd nm python3; do
    command -v "$b" >/dev/null 2>&1 || missing+=("$b")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    err "Tidak ditemukan: ${missing[*]}"
    exit 1
  fi
}

has() { command -v "$1" >/dev/null 2>&1; }

require_target() {
  if [[ -z "$TARGET" ]]; then
    read -rp "File target (binary/ELF): " TARGET
  fi
  if [[ ! -f "$TARGET" ]]; then
    err "File tidak ada: $TARGET"
    exit 1
  fi
  # deteksi arsitektur dari file (untuk pesan yang benar)
  mapfile -t FTYPE < <(file "$TARGET")
  ARCH=""
  if [[ "${FTYPE[*]}" == *x86-64* ]]; then ARCH="x64";
  elif [[ "${FTYPE[*]}" == *i386* || "${FTYPE[*]}" == *x86-32* ]]; then ARCH="x86";
  elif [[ "${FTYPE[*]}" == *ARM*aarch64* || "${FTYPE[*]}" == *ARM64* ]]; then ARCH="arm64";
  elif [[ "${FTYPE[*]}" == *ARM* ]]; then ARCH="arm";
  elif [[ "${FTYPE[*]}" == *RISC-V* ]]; then ARCH="riscv";
  elif [[ "${FTYPE[*]}" == *MIPS* ]]; then ARCH="mips";
  else ARCH="unknown"; fi
}

# py <script> [args] - jalankan python inline, stdin bebas
py() {
  "$PY" -c "$1" "${@:2}"
}

# ----------------------------- INIT / TARGET ------------------------------

# set_mode <type|elf> : aktifkan dukungan tool per jenis
arch_of() { echo "$ARCH"; }

# ------------------------------- INFO FILE --------------------------------
cmd_info() {
  require_target
  echo ""
  say "Informasi binary: $TARGET"

  echo ""
  echo -e "${STYLE}== Tipe file ==${RESET}"
  file "$TARGET"

  echo ""
  echo -e "${STYLE}== Header (readelf -h) ==${RESET}"
  readelf -h "$TARGET" 2>/dev/null | sed -n '1,25p'

  echo ""
  echo -e "${STYLE}== Protection (keamanan level) ==${RESET}"
  check_security

  echo ""
  echo -e "${STYLE}== Dynamic / Import ==${RESET}"
  if has rabin2; then
    rabin2 -i "$TARGET" 2>/dev/null | head -40
  else
    readelf -s "$TARGET" 2>/dev/null | grep -iE 'UND' | head -40
  fi

  echo ""
  echo -e "${STYLE}== Export (fungsi yang terlihat, = tidak stripped?) ==${RESET}"
  if has nm; then
    nm -n "$TARGET" 2>/dev/null | grep -iE ' T | t ' | head -80
    if nm "$TARGET" 2>/dev/null | grep -qE ' T | t '; then
      ok "Binary TIDAK stripped -> nama fungsi terbaca."
    else
      warn "Tidak ada simbol fungsi - kemungkinan STRIPPED (lihat info string/section)."
    fi
  fi
}

check_security() {
  local relro="" nx="" pie="" canary=""
  if readelf -l "$TARGET" 2>/dev/null | grep -q 'GNU_RELRO'; then
    readelf -d "$TARGET" 2>/dev/null | grep -q 'BIND_NOW' && relro="FULL RELRO" || relro="PARTIAL RELRO"
  else
    relro="NO RELRO"
  fi
  readelf -l "$TARGET" 2>/dev/null | grep -q 'GNU_STACK.*RW' && nx="NX DISABLED" || nx="NX ENABLED"
  readelf -h "$TARGET" 2>/dev/null | grep -qi 'DYN' && pie="PIE ENABLED" || pie="No PIE"
  readelf -s "$TARGET" 2>/dev/null | grep -qi '__stack_chk_fail' && canary="Canary ENABLED" || canary="No canary"
  echo "  RELRO: $relro | $nx | $pie | $canary"
  local hard=0 msg=""
  [[ "$relro" == "FULL RELRO" ]] && ((hard++))
  [[ "$nx" == "NX ENABLED" ]] && ((hard++))
  [[ "$pie" == "PIE ENABLED" ]] && ((hard++))
  [[ "$canary" == "Canary ENABLED" ]] && ((hard++))
  if (( hard >= 3 )); then
    msg="Protection kuat (${hard}/4) - bukan target exploit pemula; cari flag via strings/reversing."
  elif (( hard == 0 )); then
    msg="Tanpa protection (${hard}/4) - mungkin target buffer overflow/ret2libc."
  else
    msg="Protection sebagian (${hard}/4)."
  fi
  warn "$msg"
}

# ------------------------------- STRINGS ----------------------------------
# cari_string <target> [pola] [min-len]
cari_string() {
  local t="$1" pat="${2:-}" min="${3:-4}"
  local o
  if [[ -n "$pat" ]]; then
    o=$(strings -n "$min" "$t" 2>/dev/null | grep -aiE "$pat")
  else
    o=$(strings -n "$min" "$t" 2>/dev/null)
  fi
  printf '%s\n' "$o"
}

# flag-hunt: cari pola yang sering jadi flag
flag_hunt() {
  local t="$1"
  local IFS=','
  echo -e "${STYLE}== Pencarian flag (prefix: $FLAGPREFIX) ==${RESET}"
  local IFS_SAV="$IFS"
  for pat in $FLAGPREFIX; do
    [[ -z "$pat" ]] && continue
    local m
    m=$(cari_string "$t" "$pat" 4)
    if [[ -n "$m" ]]; then
      ok "pola '${pat}':"
      printf '%s\n' "$m" | head -8 | flaghl | sed 's/^/    /'
    fi
  done
  IFS="$IFS_SAV"
}

cmd_strings() {
  local pat="${ARGS:-}"
  require_target
  echo ""
  if [[ -z "$pat" ]]; then
    say "Semua string ($TARGET), min length 4:"
    cari_string "$TARGET" "" 4 | nl -ba | head -200
  else
    say "String dengan pola '$pat':"
    cari_string "$TARGET" "$pat" 3 | sed 's/^/    /'
  fi
}

# string per-section (objdump -s lalu ambil printable), dengan address
cmd_strings_sec() {
  local sec="${ARGS:-.rodata}"
  require_target
  echo ""
  say "String di section '$sec' (dengan alamat):"
  objdump -s -j "$sec" "$TARGET" 2>/dev/null | python3 -c '
import sys,re
out=b""
base=None
for raw in sys.stdin.buffer:
    line=raw.decode("latin1")
    if not re.match(r"\s+[0-9a-f]{4,8}\s+[0-9a-f]{8}", line): continue
    parts=line.split()
    addr=int(parts[0],16)
    if base is None: base=addr
    for tok in parts[1:]:
        if re.fullmatch(r"[0-9a-f]{4,16}",tok):
            h=tok if len(tok)%2==0 else "0"+tok
            out+=bytes.fromhex(h)
        elif tok.startswith("0x"):
            pass
        else:
            break
cur=re.compile(rb"[\x20-\x7e]{4,}")
for m in cur.finditer(out):
    s=m.group(0).decode()
    print("  0x%06x  %s" % (base+m.start(), s))
' | head -60
}

# ------------------------------- SECTION ----------------------------------
cmd_section() {
  local sec="${ARGS:-}"
  require_target
  echo ""
  say "Daftar section:"
  if [[ -n "$sec" ]]; then
    info "Filter: '$sec'"
    readelf -S "$TARGET" 2>/dev/null | grep -aiE "$sec|Section Headers|Name" 
  else
    readelf -S "$TARGET" 2>/dev/null
  fi
  echo ""
  info "Untuk lihat isi section:  data <nama>  atau  hex <nama>"
}

# ------------------------------- DISASM -----------------------------------
# list fungsi
cmd_funcs() {
  require_target
  echo ""
  say "Daftar fungsi ($TARGET):"
  if has nm && nm "$TARGET" 2>/dev/null | grep -qE ' T '; then
    nm -n "$TARGET" 2>/dev/null | grep -E ' T ' | sed 's/^/    /'
  else
    warn "nm tidak menampilkan fungsi (binary stripped?). Coba rabin2 / objdump:"
    if has rabin2; then
      rabin2 -s "$TARGET" 2>/dev/null | grep -iE ' FUNC ' | sed 's/^/    /' | head -60
    else
      objdump -t "$TARGET" 2>/dev/null | grep -iE ' F ' | sed 's/^/    /' | head -60
    fi
  fi
}

# disasm satu fungsi (by name) atau alamat
cmd_disasm() {
  local what="${ARGS:-main}"
  require_target
  echo ""
  say "Disassembly fungsi '$what' ($TARGET):"
  local archflag=""
  case "$ARCH" in
    x64)  archflag="-M intel" ;;
    x86)  archflag="-M intel" ;;
    arm64) archflag="" ;;
    *)    archflag="" ;;
  esac
  objdump -d $archflag --no-show-raw-insn "$TARGET" 2>/dev/null | \
    awk -v fn="$what" '
      BEGIN{on=0}
      /^[0-9a-f]+ <.*>:/ {
        # mulai function <nama>
        line=$0
        if (line ~ "<"fn">:") { on=1; print line; next }
        else if (on) exit          # sampai fungsi berikutnya berhenti
      }
      on{print}
    ' | head -200
}

# cari referensi: alamat panggilan
cmd_refs() {
  local what="${ARGS:-main}"
  require_target
  echo ""
  say "Referensi / panggilan ke '$what':"
  objdump -d -M intel "$TARGET" 2>/dev/null | grep -aiE "(call|jmp).*<${what//./\\.}" | sed 's/^/    /' | head -40
}

# string yang dipakai sebuah fungsi: cari alamat string yang direferensikan
# via lea [rip+disp] / mov $imm, lalu resolusi ke .rodata
cmd_func_strings() {
  local func="${ARGS:-main}"
  require_target
  echo ""
  say "String yang direferensikan fungsi '$func':"
  # ambil disasm fungsi tsb
  local asmfile="/tmp/re_func_$$.asm"
  objdump -d -M intel "$TARGET" 2>/dev/null | awk -v fn="$func" '
    BEGIN{on=0}
    /^[0-9a-f]+ <.*>:/{
      if ($0 ~ "<"fn">:") { on=1; print; next }
      else if(on) exit
    }
    on{print}
  ' > "$asmfile"
  python3 - "$TARGET" "$asmfile" "$func" <<'PY'
import sys,re,subprocess
tgt,afile,func=sys.argv[1],sys.argv[2],sys.argv[3]
data=open(tgt,'rb').read()
out=subprocess.run(['readelf','-SW',tgt],capture_output=True,text=True).stdout
secs=[]   # (name, addr, off, size)
for line in out.splitlines():
    m=re.match(r'\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)',line)
    if m: secs.append((m.group(1),int(m.group(2),16),int(m.group(3),16),int(m.group(4),16)))
def sect_of(v):
    for n,a,o,s in secs:
        if a<=v<a+s: return n,o+(v-a)
    return None,None
asm=open(afile).read()
refs=sorted({int(m.group(2),16) for m in re.finditer(r'\[rip\+0x([0-9a-f]+)\]\s*#\s*([0-9a-f]+)',asm)})
if not refs:
    print(f"  (fungsi '{func}' tidak memuat string literal via lea[rip+X])")
    sys.exit(0)
print(f"  String literal yang dipakai fungsi '{func}':")
for v in refs:
    n,off=sect_of(v)
    if off is None:
        print(f"    0x{v:x}  (di luar section)")
        continue
    end=data.find(b'\x00',off)
    blob=data[off:end if end!=-1 else off+64]
    txt=blob.decode('latin1')
    if txt.strip():
        print(f"    0x{v:x}  [{n}]  {txt!r}")
PY
  rm -f "$asmfile"
}

# ------------------------------- DATA -------------------------------------
cmd_data() {
  local sec="${ARGS:-.rodata}"
  require_target
  echo ""
  say "Isi section '$sec':"
  objdump -s -j "$sec" "$TARGET" 2>/dev/null | head -80
  echo ""
  warn "Jika binary (bukan teks) -> pakai  data.hex <nama>  untuk hexdump penuh."
}

cmd_data_hex() {
  local sec="${ARGS:-.rodata}"
  require_target
  echo ""
  say "Hexdump section '$sec':"
  objdump -s -j "$sec" "$TARGET" 2>/dev/null | more_or_head 120
  # bisa juga xxd dari offset - cari offset section
  local off=$(readelf -S "$TARGET" 2>/dev/null | grep -m1 "$sec" | awk '{print $4}')
  if [[ -n "$off" && "$off" != "0" ]]; then
    info "Atau hexdump mentah dari offset $off:"
    xxd -l 512 -s "0x$off" "$TARGET" 2>/dev/null | head -32
  fi
}

more_or_head() {
  if has less; then
    # non-interactive: head
    head -n "$1"
  else
    head -n "$1"
  fi
}

# hidden strings di section non-teks (memori terlihat printable)
cmd_hidden() {
  require_target
  echo ""
  say "Mencari string tersembunyi di seluruh section data (.data/.bss/.rodata/...):"
  for sec in .rodata .data .bss .got; do
    o=$(objdump -s -j "$sec" "$TARGET" 2>/dev/null | grep -aoE '[A-Za-z0-9_{}()/.-]{6,}' 2>/dev/null)
    if [[ -n "$o" ]]; then
      echo "  [$sec]:"
      printf '%s\n' "$o" | grep -aE '\{|\}|KTCG|flag|key|secret|pass' | sed 's/^/      /'
      printf '%s\n' "$o" | head -15 | sed 's/^/      /'
    fi
  done
}

# ------------------------------- CRYPTO / REVERSE -------------------------
# XOR bruteforce single-byte -> cari string terbaca
cmd_xor() {
  require_target
  local blobarg="${ARGS:-}"
  echo ""
  say "XOR bruteforce single-byte key ($TARGET)"
  python3 - "$TARGET" "$blobarg" <<'PY'
import sys,re
fn,blobarg=sys.argv[1],sys.argv[2]
src=""
if blobarg:
    blobarg=blobarg.replace("0x","").replace(" ","").replace(",","")
    if all(c in "0123456789abcdefABCDEF" for c in blobarg) and len(blobarg)%2==0:
        data=bytes.fromhex(blobarg); src=f"hex ({len(data)} bytes)"
    else:
        data=blobarg.encode(); src="string"
else:
    data=open(fn,'rb').read(); src=f"file {fn} ({len(data)} bytes)"
def p(b): return (9<=b<=13) or (32<=b<127)
def letter(b): return (65<=b<=90) or (97<=b<=122) or b==32
warn=f"Ciphertext dari {src}"
print(f"  Ciphertext: {src}")
print("  Mencari key (0x00-0xff) yang memunculkan teks terbaca...")
results=[]
for k in range(256):
    out=bytes(x^k for x in data)
    pr=sum(1 for c in out if p(c))/len(out) if out else 0
    distinct=len(set(out))/len(out) if out else 0
    txt=out.decode('latin1','replace').rstrip('\x00')
    if pr>=0.6 and len(out)>=6:
        score=pr*100
        if re.search(r'[A-Za-z]{4,}',txt): score+=5
        if '{' in txt: score+=8
        if '_' in txt: score+=3
        if txt.startswith(('flag{','FLAG{','CTF{','KCTF{')): score+=15
        results.append((score,pr,k,txt))
results.sort(reverse=True)
if not results:
    print("  (tidak ada key yang menghasilkan teks terbaca - cek apakah cipher tidak single-byte XOR)")
    sys.exit(0)
print("  Urutan terbaik (key -> hasil decrypt):")
seen=set(); n=0
for sc,pr,k,txt in results:
    if txt in seen: continue
    seen.add(txt); n+=1
    ch=chr(k) if 32<=k<127 else '.'
    flaggy="  <== FLAG?" if re.search(r'\{[^}\n]{3,}\}',txt) else ""
    print(f"  key 0x{k:02x} ('{ch}') pr{pr:.0%}:  {txt[:120]}{flaggy}")
    if n>=12: break
PY
}


# find embedded keys/iv/literals
cmd_keys() {
  require_target
  echo ""
  say "Mencari key/IV/literal mencurigakan:"
  python3 - "$TARGET" <<'PY'
import sys,re,base64
fn=sys.argv[1]
data=open(fn,'rb').read()
try:
    s=data.decode('latin1')
except: s=''
print("  [1] String yang mirip key (32 hex / base64 44 char / kata key):")
for m in re.finditer(r'(?i)(key|iv|salt|secret|pass|token)\s*[=:]\s*([0-9A-Za-z+/=]{8,})', s):
    if not m.group(2).startswith(('0x','0X')):
        print(f"      {m.group(0)}")
print("  [2] Blok base64 panjang (kemungkinan payload/flag terenkripsi):")
for m in re.finditer(r'[A-Za-z0-9+/=]{40,}', s):
    print(f"      ...{m.group(0)[:80]}...")
print("  [3] Hex blok panjang:")
for m in re.finditer(r'(?:0x)?[0-9a-fA-F]{32,}', s):
    if not m.group(0).startswith('0x1') and len(m.group(0))<200:
        print(f"      {m.group(0)[:80]}")
print("  [4] Format-flag / kurung kurawal di string:")
for m in re.finditer(r'[A-Za-z0-9_\-]{3,}\{[^}]{0,60}\}', s):
    print(f"      {m.group(0)}")
PY
}

# entropy tinggi -> kemungkinan encrypted/packed
cmd_entropy() {
  require_target
  echo ""
  say "Estimasi entropi per section (tinggi = mungkin terenkripsi/packed):"
  python3 - "$TARGET" <<'PY'
import sys,subprocess,re,math,collections
fn=sys.argv[1]
# dapatkan offset & size tiap section via readelf -SW (wide)
out=subprocess.run(['readelf','-SW',fn],capture_output=True,text=True).stdout
data=open(fn,'rb').read()
for line in out.splitlines():
    m=re.match(r'\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)',line)
    if not m: continue
    name,off,size,align=m.group(1),int(m.group(3),16),int(m.group(4),16),m.group(2)
    if size==0: continue
    blob=data[off:off+size]
    if not blob: continue
    c=collections.Counter(blob)
    n=len(blob)
    ent=-sum((v/n)*math.log2(v/n) for v in c.values())
    flag="HIGH (encrypted/packed?)" if ent>6.5 else ("mid" if ent>4 else "low")
    print(f"  {name:<20} size={size:>8}  entropi={ent:5.2f}  {flag}")
PY
}

# ------------------------------- DYNAMIC ----------------------------------
cmd_run() {
  require_target
  local exe="$TARGET"
  [[ "$exe" != */* ]] && exe="./$exe"
  echo ""
  say "Jalankan program + library call (ltrace):"
  if has ltrace; then
    ltrace -e printf -e puts -e fgets -e strchr "$exe"
  else
    warn "ltrace tidak ada - hanya jalankan:"
    "$exe"
  fi
}

cmd_strace() {
  require_target
  local exe="$TARGET"
  [[ "$exe" != */* ]] && exe="./$exe"
  echo ""
  say "System call trace (strace):"
  if has strace; then
    strace -f -e trace=file,read,write,open,close "$exe" 2>&1 | head -40
  else
    err "strace tidak terpasang."
  fi
}

cmd_radare() {
  require_target
  echo ""
  if has rabin2; then
    say "rabin2 - ringkasan cepat:"
    rabin2 -I "$TARGET" 2>/dev/null | head -30
    echo ""
    info "Strings via rabin2:"
    rabin2 -z "$TARGET" 2>/dev/null | grep -aiE '\.rodata|KTCG|flag|key' | head -30
  else
    warn "rabin2 tidak ada - pakai  strings / objdump."
  fi
}

# ------------------------------- FLAG / MAIN FINDER -----------------------
cmd_flag() {
  require_target
  echo ""
  say "Pencarian flag cepat (prefix: $FLAGPREFIX)"

  echo -e "${STYLE}== strings ==${RESET}"
  local found=""
  found=$(strings -n 5 "$TARGET" 2>/dev/null | grep -aiE "$FLAGREGEX|\{[^}]{3,}\}")
  if [[ -n "$found" ]]; then
    ok "Ditemukan lewat strings:"
    printf '%s\n' "$found" | flaghl | sed 's/^/    /'
  else
    warn "Tidak langsung terlihat di strings - coba disasm / crypto."
  fi

  echo -e "${STYLE}== objdump .rodata ==${RESET}"
  objdump -s -j .rodata "$TARGET" 2>/dev/null | grep -aiE "$FLAGREGEX|\{" | flaghl | sed 's/^/    /'

  echo -e "${STYLE}== rabin2 (jika ada) ==${RESET}"
  if has rabin2; then
    rabin2 -z "$TARGET" 2>/dev/null | grep -aiE "$FLAGREGEX|\{" | flaghl | sed 's/^/    /'
  fi

  echo -e "${STYLE}== auto-decode chain ==${RESET}"
  local candidates
  candidates=$(auto_encode_candidates)
  if [[ -n "$candidates" ]]; then
    while IFS= read -r cand; do
      [[ -z "$cand" || "${#cand}" -lt 6 ]] && continue
      auto_decode_candidate "$cand"
    done <<< "$candidates"
  else
    info "(tidak ada kandidat ter-encode yang terlihat)"
  fi

  warn "Flag biasanya di .rodata / .data / string literal yang tidak dipanggil."
}

# auto_encode_candidates: kumpulkan string yang mungkin flag TERENCODE
# (brace-flag, base64-look, hex-look) dari seluruh binary
auto_encode_candidates() {
  strings -n 8 "$TARGET" 2>/dev/null | python3 -c '
import sys,re
for line in sys.stdin:
    s=line.strip()
    if not s: continue
    braced = bool(re.search(r"\{[^}]{2,}\}", s))
    b64 = len(re.sub(r"[^A-Za-z0-9+/=]","",s))>=12 and re.fullmatch(r"[A-Za-z0-9+/=]+",s)
    hexl = len(s)%2==0 and len(s)>=16 and re.fullmatch(r"[0-9a-fA-F]+",s)
    if braced or b64 or hexl:
        print(s)
' | head -8
}

auto_decode_candidate() {
  local txt="$1"
  # sudah plaintext & match prefix -> flag langsung
  local re='^[A-Za-z0-9_{}.!?,:;/\-]+$'
  if [[ "$txt" =~ $re ]] && flag_matches "$txt"; then
    echo -e "  ${GRN}[F]${RESET} $txt"
    return
  fi
  # helper: cek berapa persen output printable
  printable_pct() {
    printf '%s' "$1" | python3 -c 'import sys;b=sys.stdin.buffer.read();print(sum(1 for x in b if 32<=x<127)*100//max(len(b),1))' 2>/dev/null
  }
  local decoded pr
  decoded=$(printf '%s' "$txt" | base64 -d 2>/dev/null) || true
  if [[ -n "$decoded" ]]; then
    pr=$(printable_pct "$decoded")
    if [[ "$pr" -ge 60 ]] && flag_matches "$decoded"; then
      echo -e "  ${ORG}[B64]${RESET} base64($txt) -> ${GRN}$decoded${RESET}"
    fi
  fi
  local hexd
  hexd=$(printf '%s' "$txt" | sed 's/0x//g' | xxd -r -p 2>/dev/null)
  if [[ -n "$hexd" ]]; then
    pr=$(printable_pct "$hexd")
    if [[ "$pr" -ge 60 ]] && flag_matches "$hexd"; then
      echo -e "  ${ORG}[HEX]${RESET} hex($txt) -> ${GRN}$hexd${RESET}"
    fi
  fi
}

cmd_main() {
  require_target
  echo ""
  say "Lokasi fungsi main & alur program:"
  local archflag="-M intel"
  case "$ARCH" in arm64|arm) archflag="";; esac
  objdump -d $archflag "$TARGET" 2>/dev/null | grep -E '<main>:' | sed 's/^/    /'
  echo ""
  info "Fungsi main (disassembly):"
  cmd_disasm main
}

# ------------------------------- MENU -------------------------------------
main_menu() {
  local m
  while true; do
    echo ""
    echo "======================================================================"
    echo -e "  ${STYLE}Reverse Engineering Toolkit${RESET}"
    echo "======================================================================"
    if [[ -n "$TARGET" ]]; then
      echo -e "  Target : ${GRN}$TARGET${RESET}  (${ARCH})"
    else
      echo -e "  Target : ${YLW}(belum dipilih)${RESET}"
    fi
    echo "----------------------------------------------------------------------"
    echo "  [INFO]    1) Info file + protection     2) Flag cepat"
    echo "  [STRINGS] 3) Semua string               4) Cari string (pola)"
    echo "            5) String per-section         6) Flag hunt (pola umum)"
    echo "  [SECTION] 7) Daftar section             8) Isi section"
    echo "            9) Section hexdump           10) Hidden string"
    echo "  [DISASM] 11) Daftar fungsi             12) Disasm fungsi"
    echo "           13) Referensi panggilan       14) String dipakai fungsi"
    echo "  [DATA]   15) Dump .rodata/.data        16) Extract data"
    echo "  [CRYPTO] 17) XOR bruteforce            18) Cari key/IV/flag"
    echo "           19) Entropi (paket/enkripsi)  20) Main & alur"
    echo "  [DYN]    21) Run + ltrace              22) strace"
    echo "           23) rabin2/r2 quick"
    echo "----------------------------------------------------------------------"
    echo "  T) Pilih target   Q) Keluar"
    echo "----------------------------------------------------------------------"
    read -rp "Pilih: " m
    case "$m" in
      1) cmd_info;;
      2) cmd_flag;;
      3) ARGS=""; cmd_strings;;
      4) read -rp "  Pola string (regex): " pat; ARGS="$pat"; cmd_strings;;
      5) read -rp "  Section [.rodata]: " sec; ARGS="${sec:-.rodata}"; cmd_strings_sec;;
      6) flag_hunt_block;;
      7) cmd_section;;
      8) read -rp "  Section [.rodata]: " sec; ARGS="${sec:-.rodata}"; cmd_data;;
      9) read -rp "  Section [.rodata]: " sec; ARGS="${sec:-.rodata}"; cmd_data_hex;;
     10) cmd_hidden;;
     11) cmd_funcs;;
     12) read -rp "  Fungsi [main]: " f; ARGS="${f:-main}"; cmd_disasm;;
     13) read -rp "  Fungsi [main]: " f; ARGS="${f:-main}"; cmd_refs;;
     14) read -rp "  Fungsi [main]: " f; ARGS="${f:-main}"; cmd_func_strings;;
     15) cmd_data;;
     16) cmd_hidden;;
     17) cmd_xor;;
     18) cmd_keys;;
     19) cmd_entropy;;
     20) cmd_main;;
     21) cmd_run;;
     22) cmd_strace;;
     23) cmd_radare;;
      [tT]) read -rp "  Target: " TARGET; require_target;;
      [qQ]) exit 0;;
      *) warn "Pilihan tidak dikenal: $m";;
    esac
  done
}

flag_hunt_block() {
  require_target
  echo ""
  echo -e "${STYLE}== Pencarian flag (prefix: $FLAGPREFIX) ==${RESET}"
  local IFS=','
  local IFS_SAV="$IFS"
  for pat in $FLAGPREFIX; do
    [[ -z "$pat" ]] && continue
    local m
    m=$(cari_string "$TARGET" "$pat" 4)
    if [[ -n "$m" ]]; then
      ok "pola '${pat}':"
      printf '%s\n' "$m" | head -6 | flaghl | sed 's/^/    /'
    fi
  done
  IFS="$IFS_SAV"
}

# ------------------------------ DISPATCH ----------------------------------
usage() {
  echo ""
  echo "Cara pakai:"
  echo "  $0                                   -> menu interaktif"
  echo "  $0 <file>                            -> analisis cepat (info + flag)"
  echo "  $0 info <file>"
  echo "  $0 strings <file> [pola]"
  echo "  $0 section <file> [nama]"
  echo "  $0 disasm <file> [fungsi]"
  echo "  $0 data <file> [section]"
  echo "  $0 crypto <file>"
  echo "  $0 xor <file> [hex-ciphertext]"
  echo "  $0 keys <file>"
  echo "  $0 entropy <file>"
  echo "  $0 run <file> [args...]"
  echo "  $0 flag <file>"
  echo ""
  echo "Flag prefix (penting!):"
  echo "  $0 --prefix 'KTCG,CTF,{}' flag <file>"
  echo "  export FLAGPREFIX='KTCG,MyCTF,flag'  $0 <file>"
  echo "  echo 'FLAGPREFIX=KTCG,{}' > .re_tool.conf"
  echo ""
  echo "Sub-perintah: info strings section disasm data crypto xor keys"
  echo "              entropy run strace radare flag funcs main refs hidden"
}

dispatch() {
  local c="${1:-}"; shift || true
  case "$c" in
    info)     require_target; cmd_info;;
    strings)  require_target; ARGS="${1:-}"; cmd_strings;;
    section)  require_target; ARGS="${1:-}"; cmd_section;;
    disasm)   require_target; ARGS="${1:-main}"; cmd_disasm;;
    funcs)    require_target; cmd_funcs;;
    refs)     require_target; ARGS="${1:-main}"; cmd_refs;;
    fstrings) require_target; ARGS="${1:-main}"; cmd_func_strings;;
    data)     require_target; ARGS="${1:-.rodata}"; cmd_data;;
    hex)      require_target; ARGS="${1:-.rodata}"; cmd_data_hex;;
    hidden)   require_target; cmd_hidden;;
    crypto)   require_target; ARGS="${1:-}"; cmd_keys;;
    xor)      require_target; ARGS="${1:-}"; cmd_xor;;
    keys)     require_target; ARGS="${1:-}"; cmd_keys;;
    entropy)  require_target; cmd_entropy;;
    run)      require_target; cmd_run;;
    strace)   require_target; cmd_strace;;
    radare)   require_target; cmd_radare;;
    flag)     require_target; cmd_flag;;
    main)     require_target; cmd_main;;
    stringssec) require_target; ARGS="${1:-.rodata}"; cmd_strings_sec;;
    *) usage; exit 1;;
  esac
}

# ----------------------------- MAIN ---------------------------------------
main() {
  need_check
  local CLI_PREFIX=""
  # --- parse --prefix sebelum semua ---
  local args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --prefix) CLI_PREFIX="${2:-}"; shift 2;;
      -p)        CLI_PREFIX="${2:-}"; shift 2;;
      *) args+=("$1"); shift;;
    esac
  done
  set -- "${args[@]}"
  export CLI_PREFIX
  load_flag_prefix

  # quick: $0 <file> -> analisis cepat
  if [[ $# -ge 1 && -f "$1" ]]; then
    TARGET="$1"; shift
    if [[ $# -eq 0 ]]; then
      require_target
      echo ""
      say "Analisis cepat $TARGET"
      cmd_info
      echo ""
      cmd_flag
      echo ""
      info "Gunakan 'menu' untuk mode interaktif penuh:  $0 menu -- dan pilih target"
      exit 0
    fi
    dispatch "$@"
    exit 0
  fi
  if [[ $# -ge 1 ]]; then
    case "$1" in
      -h|--help|help) usage; exit 0;;
      menu) :;;       # lalu jatuh ke menu
      info|strings|section|disasm|funcs|refs|fstrings|data|hex|hidden|crypto|xor|keys|entropy|run|strace|radare|flag|main|stringssec)
        local cmd="$1"; TARGET="${2:-}"
        require_target
        dispatch "$cmd" "${3:-}"; exit 0;;
      *) err "Usage: $0 [file] | <cmd> <file> | -h"; exit 1;;
    esac
  fi
  main_menu
}

main "$@"
