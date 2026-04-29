#!/bin/bash
# boltimage.sh — bake a flat PNG into ~/.lockbg.rgb for bolt.
#
# Usage:  boltimage.sh [src.png]
#         (default src: ~/bolt.png)
#
# Resizes src to 1920x1200 (fit + center, padded with bg_color) and
# writes raw RGB. bolt mmaps ~/.lockbg.rgb at startup and blits it as
# the lock background — no logo overlay, no tagline rendering.

set -e

SRC=${1:-$HOME/bolt.png}
DST=$HOME/.lockbg.rgb
W=1920
H=1200
BG='#000000'

[[ -f $SRC ]] || { echo "boltimage: $SRC not found" >&2; exit 1; }
command -v convert >/dev/null || { echo "boltimage: ImageMagick convert required" >&2; exit 1; }

convert "$SRC" -resize ${W}x${H} -background "$BG" -gravity center -extent ${W}x${H} -depth 8 "RGB:$DST"

echo "boltimage: $SRC -> $DST ($(stat -c %s "$DST") bytes, ${W}x${H})"
