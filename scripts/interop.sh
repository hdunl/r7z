#!/usr/bin/env bash
# Two-way interoperability check against 7-Zip.
#   scripts/interop.sh [path/to/r7z] [path/to/7z] [corpus-dir]
# Every archive r7z writes must test and extract identically with 7-Zip, and every
# archive 7-Zip writes must test and extract identically with r7z.
set -u
R=${1:-target/release/r7z}
Z=${2:-7z}
CORPUS=${3:-}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
pass=0
fail=0

if [ -z "$CORPUS" ]; then
  CORPUS=$WORK/corpus
  mkdir -p "$CORPUS/src/deep/er/est" "$CORPUS/bin" "$CORPUS/empty dir" "$CORPUS/ünïcødé 名前"
  for i in $(seq 1 2000); do echo "line $i: the quick brown fox $((i * 7919 % 1013))"; done > "$CORPUS/src/log.txt"
  cp "$0" "$CORPUS/src/deep/er/est/script.sh"
  head -c 2000000 /dev/urandom > "$CORPUS/bin/random.bin"
  : > "$CORPUS/empty.txt"
  echo "héllo" > "$CORPUS/ünïcødé 名前/naïve.txt"
  # Executable-looking data so the BCJ path runs.
  head -c 300000 /dev/urandom | od -An -tx1 | head -c 400000 > "$CORPUS/bin/tool.dll"
fi
NAME=$(basename "$CORPUS")
PARENT=$(dirname "$CORPUS")

check() { # label, command...
  local label=$1; shift
  if "$@" >"$WORK/log" 2>&1; then
    pass=$((pass + 1)); printf '  ok    %s\n' "$label"
  else
    fail=$((fail + 1)); printf '  FAIL  %s\n' "$label"; sed 's/^/        /' "$WORK/log" | tail -15
  fi
}

same_tree() { diff -r "$CORPUS" "$1/$NAME" >/dev/null; }

r_to_z() { # label, r7z switches...
  local label=$1; shift
  local arc=$WORK/r.7z out=$WORK/out
  rm -rf "$arc" "$out"
  check "r7z $label → 7z" bash -c "cd '$PARENT' && '$R' a -bd '$arc' '$NAME' $* && '$Z' t -bd $PW_Z '$arc' && '$Z' x -bd -y $PW_Z -o'$out' '$arc' && diff -r '$CORPUS' '$out/$NAME'"
}

z_to_r() { # label, 7z switches...
  local label=$1; shift
  local arc=$WORK/z.7z out=$WORK/out
  rm -rf "$arc" "$out"
  check "7z $label → r7z" bash -c "cd '$PARENT' && '$Z' a -bd '$arc' '$NAME' $* && '$R' t -bd $PW_R '$arc' && '$R' x -bd -y $PW_R -o'$out' '$arc' && diff -r '$CORPUS' '$out/$NAME'"
}

echo "r7z → 7-Zip"
PW_Z=""
for sw in "" "-mx1" "-mx3" "-mx7" "-mx9" "-mx0" "-ms=off" "-mmt1" "-m0=lzma" "-m0=copy" "-mf=off" "-mf=Delta:4" "-mf=BCJ" "-mhc=off" "-m0=lzma2:c=1m"; do
  r_to_z "${sw:-default}" $sw
done
PW_Z="-psecret"
r_to_z "-psecret" -psecret
r_to_z "-psecret -mhe=on" -psecret -mhe=on
r_to_z "-psecret -ms=off" -psecret -ms=off

echo "7-Zip → r7z"
PW_R=""
for sw in "" "-mx1" "-mx3" "-mx7" "-mx9" "-mx0" "-ms=off" "-mmt1" "-m0=lzma" "-m0=copy" "-mf=off" "-mf=Delta:4" "-mf=ARM64" "-m0=lzma2:c=1m"; do
  z_to_r "${sw:-default}" $sw
done
PW_R="-psecret"
z_to_r "-psecret" -psecret
z_to_r "-psecret -mhe=on" -psecret -mhe=on
z_to_r "-psecret -ms=off" -psecret -ms=off

echo "formats: r7z → 7-Zip"
mkdir -p "$WORK/fmt"
# Extracts with 7-Zip; when that yields a lone .tar or .cpio (7-Zip opens .tar.gz one
# level at a time), that is extracted too.
z_extract() { # archive outdir [switches]
  local arc=$1 out=$2; shift 2
  "$Z" x -bd -y "$@" -o"$out" "$arc" >/dev/null || return 1
  local inner
  inner=$(ls "$out")
  if [ "$(ls "$out" | wc -l)" -eq 1 ] && [[ "$inner" == *.tar || "$inner" == *.cpio ]]; then
    "$Z" x -bd -y -o"$out" "$out/$inner" >/dev/null && rm "$out/$inner"
  fi
}
fresh() { rm -rf "$WORK/fmt"; mkdir -p "$WORK/fmt"; }
fmt_r2z() { # archive-name r7z-switches...
  local arc=$WORK/fmt/$1; shift
  fresh
  (cd "$PARENT" && "$R" a -bd "$arc" "$NAME" "$@") >/dev/null || return 1
  "$Z" t -bd $PW_Z "$arc" >/dev/null || return 1
  z_extract "$arc" "$WORK/fmt/out" $PW_Z || return 1
  diff -r "$CORPUS" "$WORK/fmt/out/$NAME"
}
single_r2z() { # extension
  local arc=$WORK/fmt/one.$1
  fresh
  "$R" a -bd "$arc" "$CORPUS/src/log.txt" >/dev/null || return 1
  "$Z" t -bd "$arc" >/dev/null || return 1
  "$Z" x -bd -y -o"$WORK/fmt/out" "$arc" >/dev/null || return 1
  cmp "$CORPUS/src/log.txt" "$WORK/fmt/out/$(ls "$WORK/fmt/out")"
}
PW_Z=""
for f in t.zip "t.zip -mx0" "t.zip -mx1" "t.zip -mx9" "t.zip -mm=Copy" "t.zip -mmt1" \
         t.tar t.tar.gz t.tgz "t.tar.gz -mx9" t.tar.bz2 "t.tar.bz2 -mx1" t.tar.xz "t.tar.xz -mx1" \
         "t.gz -tgzip"; do
  set -- $f
  name=$1; shift
  case "$name $*" in "t.gz -tgzip") name=t.tar.gz ;; esac
  check "r7z $f → 7z" fmt_r2z "$name" "$@"
done
PW_Z="-psecret"
check "r7z t.zip -psecret (AES-256) → 7z" fmt_r2z t.zip -psecret
check "r7z t.zip -psecret -mm=Copy → 7z" fmt_r2z t.zip -psecret -mm=Copy
PW_Z=""
for e in gz bz2 xz; do
  check "r7z one.$e (single file) → 7z" single_r2z "$e"
done

echo "formats: 7-Zip → r7z"
fmt_z2r() { # archive-name 7z-switches...
  local arc=$WORK/fmt/$1; shift
  fresh
  (cd "$PARENT" && "$Z" a -bd "$arc" "$NAME" "$@") >/dev/null || return 1
  "$R" t -bd $PW_R "$arc" >/dev/null || return 1
  "$R" x -bd -y $PW_R -o"$WORK/fmt/out" "$arc" >/dev/null || return 1
  diff -r "$CORPUS" "$WORK/fmt/out/$NAME"
}
tar_z2r() { # extension 7z-type: 7-Zip writes the tar, then compresses it
  fresh
  (cd "$PARENT" && "$Z" a -bd -ttar "$WORK/fmt/t.tar" "$NAME") >/dev/null || return 1
  "$Z" a -bd -t"$2" "$WORK/fmt/t.tar.$1" "$WORK/fmt/t.tar" >/dev/null || return 1
  rm "$WORK/fmt/t.tar"
  "$R" t -bd "$WORK/fmt/t.tar.$1" >/dev/null || return 1
  "$R" x -bd -y -o"$WORK/fmt/out" "$WORK/fmt/t.tar.$1" >/dev/null || return 1
  diff -r "$CORPUS" "$WORK/fmt/out/$NAME"
}
split_z2r() {
  fresh
  (cd "$PARENT" && "$Z" a -bd -v300k "$WORK/fmt/v.7z" "$NAME") >/dev/null || return 1
  "$R" t -bd "$WORK/fmt/v.7z.001" >/dev/null || return 1
  "$R" x -bd -y -o"$WORK/fmt/out" "$WORK/fmt/v.7z.001" >/dev/null || return 1
  diff -r "$CORPUS" "$WORK/fmt/out/$NAME"
}
PW_R=""
for f in "t.zip" "t.zip -mx0" "t.zip -mx9" "t.zip -mm=Deflate64" "t.zip -mm=BZip2" "t.zip -mm=LZMA" \
         "t.zip -mm=PPMd" "t.zip -mm=Copy" "t.tar" "t.7z -m0=PPMd" "t.7z -m0=BZip2" "t.7z -m0=Deflate" \
         "t.7z -m0=Deflate64"; do
  set -- $f
  name=$1; shift
  check "7z $f → r7z" fmt_z2r "$name" "$@"
done
PW_R="-psecret"
check "7z t.zip -psecret (ZipCrypto) → r7z" fmt_z2r t.zip -psecret
check "7z t.zip -psecret -mem=AES256 → r7z" fmt_z2r t.zip -psecret -mem=AES256
check "7z t.zip -psecret -mem=AES128 -mm=LZMA → r7z" fmt_z2r t.zip -psecret -mem=AES128 -mm=LZMA
PW_R=""
check "7z tar → gzip → r7z (one step)" tar_z2r gz gzip
check "7z tar → bzip2 → r7z (one step)" tar_z2r bz2 bzip2
check "7z tar → xz → r7z (one step)" tar_z2r xz xz
check "7z -v300k split volumes → r7z" split_z2r
check "7z t.wim → r7z" fmt_z2r t.wim -twim
REAL_WIM=${REAL_WIM:-/c/Windows/System32/DrtmAuthTxt.wim}
if [ -f "$REAL_WIM" ]; then
  # Defined below with the platform-tool cases; XPRESS-compressed, made by Windows.
  wim_real() { same_as_7z "$REAL_WIM"; }
fi

# Formats neither tool family writes: archives from the platform's own tools must extract
# identically with r7z and 7-Zip (and match the source tree).
PLAIN=$WORK/plain
mkdir -p "$PLAIN/sub/deeper"
cp "$CORPUS/src/log.txt" "$PLAIN/sub/"
cp "$CORPUS/bin/random.bin" "$PLAIN/"
echo "small" > "$PLAIN/sub/deeper/small.txt"
same_as_7z() { # archive
  local arc=$1 o1=$WORK/fmt/o1 o2=$WORK/fmt/o2
  rm -rf "$o1" "$o2"
  "$R" t -bd "$arc" >/dev/null || return 1
  "$R" x -bd -y -o"$o1" "$arc" >/dev/null || return 1
  z_extract "$arc" "$o2" || return 1
  diff -r "$o1" "$o2"
}
bsd() { # archive-name bsdtar-switches...
  local arc=$WORK/fmt/$1; shift
  fresh
  (cd "$PLAIN" && "$BSDTAR" -c "$@" -f "$arc" sub random.bin) || return 1
  same_as_7z "$arc"
}
if [ -n "$(type -t wim_real)" ]; then
  echo "formats: Windows-made WIM → r7z and 7-Zip"
  check "$(basename "$REAL_WIM") (XPRESS)" wim_real
fi
BSDTAR=${BSDTAR:-/c/Windows/System32/tar.exe}
if [ -x "$BSDTAR" ]; then
  echo "formats: platform tools (bsdtar) → r7z and 7-Zip"
  check "bsdtar pax tar" bsd t.tar --format pax
  check "bsdtar gnutar" bsd t.tar --format gnutar
  check "bsdtar tar.zst" bsd t.tar.zst --zstd
  check "bsdtar tar.Z (compress)" bsd t.tar.Z -Z
  check "bsdtar tar.lzma" bsd t.tar.lzma --lzma
  check "bsdtar cpio newc" bsd t.cpio --format newc
  check "bsdtar cpio odc" bsd t.cpio --format odc
  check "bsdtar cpio bin" bsd t.cpio --format bin
  check "bsdtar cpio.gz (two levels)" bsd t.cpio.gz --format newc -z
  check "bsdtar xar (gzip)" bsd t.xar --format xar
  check "bsdtar xar (bzip2)" bsd t.xar --format xar --options xar:compression=bzip2
  check "bsdtar xar (none)" bsd t.xar --format xar --options xar:compression=none
  bsd_flat() { # archive-name bsdtar-switches... (formats without directories)
    local arc=$WORK/fmt/$1; shift
    fresh
    mkdir -p "$WORK/flat"
    cp "$PLAIN/sub/log.txt" "$PLAIN/random.bin" "$WORK/flat/"
    (cd "$WORK/flat" && "$BSDTAR" -c "$@" -f "$arc" log.txt random.bin) || return 1
    same_as_7z "$arc"
  }
  check "bsdtar ar (GNU)" bsd_flat t.a --format argnu
  check "bsdtar ar (BSD)" bsd_flat t.a --format arbsd
  check "bsdtar raw .zst" bash -c "cd '$PLAIN' && '$BSDTAR' -c --format raw --zstd -f '$WORK/fmt/r.zst' random.bin && cd - >/dev/null && $(declare -f same_as_7z z_extract); R='$R' Z='$Z' WORK='$WORK' same_as_7z '$WORK/fmt/r.zst'"
fi
MAKECAB=${MAKECAB:-/c/Windows/System32/makecab.exe}
if [ -x "$MAKECAB" ] && command -v cygpath >/dev/null; then
  echo "formats: makecab → r7z and 7-Zip"
  mk_cab() { # compression-type [memory]
    fresh
    local d=$WORK/fmt/cab
    mkdir -p "$d"
    {
      echo ".Set CabinetNameTemplate=t.cab"
      echo ".Set DiskDirectoryTemplate=$(cygpath -w "$d")"
      echo ".Set CompressionType=$1"
      [ -n "${2:-}" ] && echo ".Set CompressionMemory=$2"
      echo ".Set Cabinet=on"
      echo ".Set Compress=on"
      echo ".Set MaxDiskSize=0"
      echo "\"$(cygpath -w "$PLAIN/random.bin")\" random.bin"
      echo "\"$(cygpath -w "$PLAIN/sub/log.txt")\" sub\log.txt"
      echo "\"$(cygpath -w "$PLAIN/sub/deeper/small.txt")\" sub\deeper\small.txt"
    } > "$WORK/fmt/t.ddf"
    (cd "$WORK/fmt" && "$MAKECAB" //F "$(cygpath -w "$WORK/fmt/t.ddf")") >/dev/null || return 1
    same_as_7z "$d/t.cab"
  }
  check "makecab MSZIP" mk_cab MSZIP
  check "makecab LZX:21" mk_cab LZX 21
  check "makecab LZX:15" mk_cab LZX 15
fi
BANDIZIP=${BANDIZIP:-"/c/Program Files/Bandizip/bz.exe"}
if [ -x "$BANDIZIP" ]; then
  echo "formats: Bandizip → r7z and 7-Zip"
  bz_lzh() {
    fresh
    (cd "$PLAIN" && "$BANDIZIP" c -y -fmt:lzh "$(cygpath -w "$WORK/fmt/t.lzh" 2>/dev/null || echo "$WORK/fmt/t.lzh")" sub random.bin) >/dev/null || return 1
    same_as_7z "$WORK/fmt/t.lzh"
  }
  check "Bandizip lzh (-lh7-)" bz_lzh
fi

echo "negative cases"
PW_R=""
(cd "$PARENT" && "$Z" a -bd -psecret "$WORK/enc.7z" "$NAME" >/dev/null)
check "wrong password is rejected" bash -c "! '$R' t -bd -pwrong '$WORK/enc.7z'"
(cd "$PARENT" && "$Z" a -bd -psecret -mhe=on "$WORK/hdr.7z" "$NAME" >/dev/null)
check "encrypted header needs password" bash -c "! '$R' l '$WORK/hdr.7z' </dev/null"
head -c 5000 "$WORK/enc.7z" > "$WORK/trunc.7z"
check "truncated archive is rejected" bash -c "! '$R' t -bd '$WORK/trunc.7z'"
cp "$WORK/z.7z" "$WORK/flip.7z" 2>/dev/null || (cd "$PARENT" && "$Z" a -bd "$WORK/flip.7z" "$NAME" >/dev/null)
printf '\xff' | dd of="$WORK/flip.7z" bs=1 seek=200 conv=notrunc 2>/dev/null
check "corrupted data is detected" bash -c "! '$R' t -bd '$WORK/flip.7z'"

echo
echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
