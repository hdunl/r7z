#!/usr/bin/env bash
# Makes the ext2, ext3 and ext4 test images in this directory: e2fsprogs' mke2fs populates
# each image from a small source tree (`mke2fs -d`), so the block maps, extent trees and
# directory blocks are the ones the kernel-side tools write. Each image is gzip-compressed to
# keep the checkout small; r7z opens the gzip layer, then the ext image inside it.
#   ext2-indirect : block-mapped file (100 KiB needs indirect blocks), a fast and a slow link
#   ext3-journal  : the same tree with a journal and block maps
#   ext4-extents  : extent trees, including a sparse file with more extents than an inode holds
#   ext4-inline   : inline_data: a 12-byte file in the inode, and a 100-byte one whose last 40
#                   bytes are in the system.data extended attribute (no sparse file)
# Generated with e2fsprogs 1.46.5 and gzip 1.10 (Ubuntu 22.04 under WSL). The bytes differ
# from run to run (UUIDs and mkfs times); the files inside do not.
set -eu
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
src="$work/src"
mkdir -p "$src/dir/sub"
yes 'indirect block data 0123456789' | head -c 102400 > "$src/big.txt"
printf 'short\n' > "$src/small.txt"
printf 'tiny inline\n' > "$src/tiny.txt"
head -c 100 /dev/zero | tr '\0' 'q' > "$src/medium.txt"
: > "$src/dir/sub/empty"
ln -s small.txt "$src/fast-link"
ln -s "$(printf 'a%.0s' $(seq 1 100))" "$src/slow-link"
truncate -s 1M "$src/sparse.bin"
for i in $(seq 0 15); do
  yes "page $i" | head -c 4096 | dd of="$src/sparse.bin" bs=4096 seek=$((i * 4)) conv=notrunc status=none
done
find "$src" -exec touch -h -d '2001-09-09 01:46:40' {} +
# name:mke2fs type:extra feature
for variant in ext2-indirect:ext2: ext3-journal:ext3: ext4-extents:ext4: ext4-inline:ext4:inline_data; do
  name=${variant%%:*}
  rest=${variant#*:}
  type=${rest%%:*}
  feature=${rest#*:}
  img="$work/$name.img"
  truncate -s 4M "$img"
  opts=(-q -F -t "$type" -b 1024 -L "$name" -E root_owner=0:0)
  if [ -n "$feature" ]; then
    opts+=(-O "$feature")
  fi
  tree="$src"
  if [ "$name" = ext4-inline ]; then
    # mke2fs stores a sparse file short when inline_data is on, so that image leaves it out.
    tree="$work/src-inline"
    rm -rf "$tree"
    cp -a "$src" "$tree"
    rm "$tree/sparse.bin"
  fi
  mke2fs "${opts[@]}" -d "$tree" "$img"
  gzip -9n -c "$img" > "$name.img.gz"
done
