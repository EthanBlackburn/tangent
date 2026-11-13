#!/bin/bash
# compare.sh: eslogger and the sensor at once, for a minute (or $1 seconds),
# each into its own file, and then compare.py over the two: every event both
# saw, on the fields plugin macos reads.
#
#   ./compare.sh          # 60 seconds, into a new directory only you can read
#   ./compare.sh 300 DIR  # five minutes, into DIR
#
# One sudo prompt; the terminal needs Full Disk Access, as for eslogger. The
# two files hold every command line and environment of the minute: the
# directory is yours alone, and is yours to delete.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)

secs=${1:-60}
out=${2:-$(mktemp -d "${TMPDIR:-/tmp}/sensor-compare.XXXXXX")}
sensor=$here/build/TangentSensor.app/Contents/MacOS/tangent-sensor
[ -x "$sensor" ] || { echo "no $sensor: ./build.sh PROFILE first" >&2; exit 1; }
mkdir -p "$out"
chmod 700 "$out"

sudo -v

# Each pipeline's last program is ours, not root's, so it is the one to stop:
# what is above it ends when its pipe closes.
sudo eslogger exec fork exit open close create rename unlink btm_launch_item_add tcc_modify \
  2> "$out/eslogger.err" | cat > "$out/eslogger.ndjson" &
a=$!
sudo "$sensor" 2> "$out/sensor.err" | cat > "$out/sensor.ndjson" &
b=$!

echo "capturing for $secs seconds into $out"
sleep "$secs"
kill "$a" "$b" 2>/dev/null || true
sleep 2

[ ! -s "$out/sensor.err" ] || { echo "the sensor said:"; cat "$out/sensor.err"; }
[ ! -s "$out/eslogger.err" ] || { echo "eslogger said:"; head -3 "$out/eslogger.err"; }
python3 "$here/compare.py" "$out"
