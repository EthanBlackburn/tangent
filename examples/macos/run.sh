#!/bin/bash
# run.sh: the whole example in one command. It starts tangent and the four
# things that feed it, in the order that matters, and stops them together.
#
#   ./run.sh                 # haiku.yaml, here
#   ./run.sh tangent.yaml    # a local model
#   ./run.sh /path/to/a/config.yaml    # sockets, lake and verdicts beside it
#   SAVE=1 ./run.sh          # also keep eslogger's and net.py's lines, to replay
#   SENSOR=/path/to/TangentSensor.app/Contents/MacOS/tangent-sensor ./run.sh
#                            # packs/macos/sensor in eslogger's place
#
# The order: a snapshot of what is running goes first, so the first events
# have someone above them; eslogger starts; the snapshot goes again, for what
# started in between (the plugin takes a line only for a process it does not
# know); then the network capture and the transcript reader. Before any of it
# the script names its own pid as the capture's, and the plugin leaves out
# what it and its children do: a packet capture piped to a socket is what a
# sniffer looks like, and the judge said so of this one in every run.
#
# eslogger and tcpdump need root (one sudo prompt), and the terminal this runs
# in needs Full Disk Access (System Settings, Privacy & Security). Ctrl-C
# stops everything; tangent finishes the sessions it holds first.
set -euo pipefail

config=${1:-$(dirname "$0")/haiku.yaml}
pack=$(cd "$(dirname "$0")/../../packs/macos" && pwd)
tangent=${TANGENT:-tangent}
cd "$(dirname "$config")"
config=$(basename "$config")

sudo -v

"$tangent" run --config "$config" > tangent.log 2>&1 &
tangent_pid=$!
for _ in $(seq 100); do
  [ -S es.sock ] && [ -S net.sock ] && break
  kill -0 "$tangent_pid" 2>/dev/null || { echo "tangent stopped: see $(pwd)/tangent.log" >&2; exit 1; }
  sleep 0.1
done
[ -S es.sock ] || { echo "no es.sock in $(pwd): does $config name socket sources es.sock and net.sock?" >&2; exit 1; }

now() { date -u +%Y-%m-%dT%H:%M:%S.000000000Z; }
snapshot() { python3 "$pack/ps/ps.py" | nc -U es.sock; }

# who is running, then that this script and what is under it is the capture
snapshot
echo "{\"time\":\"$(now)\",\"monitor\":{\"pid\":$$}}" | nc -U es.sock

# stdin through, and a copy kept when SAVE is set
save() {
  if [ -z "${SAVE:-}" ]; then cat
  elif [ "${2:-}" = zstd ]; then tee >(trap '' INT TERM; zstd -q -1 > "$1")
  else tee "$1"
  fi
}

# Each pipeline's last program is ours, not root's, so it is the one to stop:
# what is above it ends when its pipe closes.
capture=(eslogger exec fork exit open close create rename unlink btm_launch_item_add tcc_modify)
[ -z "${SENSOR:-}" ] || capture=("$SENSOR")   # packs/macos/sensor's binary: the same events, in the same lines
sudo "${capture[@]}" \
  | save es.raw.zst zstd | nc -U es.sock &
feeds=($!)
sleep 1
snapshot

sudo tcpdump -i pktap,all -k NP -n -l -tt -X "$(python3 "$pack/net/net.py" --filter)" 2>/dev/null \
  | python3 "$pack/net/net.py" | save net.raw.ndjson | nc -U net.sock &
feeds+=($!)

python3 "$pack/agent/transcripts.py" > >(nc -U es.sock) &
feeds+=($!)

stop() {
  trap - INT TERM
  echo
  echo "stopping: tangent is finishing the sessions it holds"
  kill "${feeds[@]}" 2>/dev/null || true
  kill -TERM "$tangent_pid" 2>/dev/null || true
  wait "$tangent_pid" 2>/dev/null || true
  exit 0
}
trap stop INT TERM

echo "capturing into $(pwd): alerts.ndjson and verdicts.ndjson. Ctrl-C to stop."
wait "$tangent_pid"
