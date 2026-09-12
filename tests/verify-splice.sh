#!/bin/sh
# Verify a spliced FLAC against its source segments with the reference tools.
#   tests/verify-splice.sh out.flac seg1.flac seg2.flac ...
# Checks: flac -t, STREAMINFO/SEEKTABLE sanity, byte-identical PCM, seeking via flac and ffmpeg.
set -e
out="$1"; shift
[ -n "$out" ] && [ $# -ge 1 ] || { echo "usage: $0 out.flac seg1.flac [seg2.flac ...]"; exit 2; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "== flac -t"
flac -t -s "$out" && echo "ok"

echo "== metadata"
metaflac --list --block-type=STREAMINFO "$out" | grep -E "blocksize|framesize|total samples|MD5"
metaflac --list --block-type=SEEKTABLE "$out" | grep -c "sample_number=" | sed 's/^/seek points (incl. placeholders): /'
metaflac --list --block-type=VORBIS_COMMENT "$out" | grep -E "comment\[" || true

echo "== PCM identity"
for f in "$@"; do flac -d -s -f --force-raw-format --endian=little --sign=signed -o - "$f"; done > "$tmp/ref.raw"
flac -d -s -f --force-raw-format --endian=little --sign=signed -o "$tmp/out.raw" "$out"
cmp "$tmp/ref.raw" "$tmp/out.raw" && echo "identical ($(wc -c < "$tmp/ref.raw") bytes)"

rate=$(metaflac --show-sample-rate "$out"); ch=$(metaflac --show-channels "$out"); bps=$(metaflac --show-bps "$out")
frame=$((ch * bps / 8))
total=$(metaflac --show-total-samples "$out")
echo "== seeking (flac --skip) at 1/3 of the stream"
skip=$((total / 3)); count=$((rate * 5))
flac -d -s -f --force-raw-format --endian=little --sign=signed --skip=$skip --until=+$count -o "$tmp/part.raw" "$out"
dd if="$tmp/ref.raw" of="$tmp/refpart.raw" bs=$frame skip=$skip count=$count status=none
cmp "$tmp/part.raw" "$tmp/refpart.raw" && echo "flac seek ok"
echo "== seeking (ffmpeg -ss) at 2/3 of the stream"
sec=$((total * 2 / 3 / rate))
ffmpeg -v error -ss $sec -i "$out" -t 3 -f s${bps}le -acodec pcm_s${bps}le - > "$tmp/ff.raw"
dd if="$tmp/ref.raw" of="$tmp/ffref.raw" bs=$frame skip=$((sec * rate)) count=$((3 * rate)) status=none
cmp -n $(wc -c < "$tmp/ff.raw") "$tmp/ff.raw" "$tmp/ffref.raw" && echo "ffmpeg seek ok"
echo "== ALL CHECKS PASSED"
