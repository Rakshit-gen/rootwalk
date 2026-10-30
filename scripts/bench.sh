#!/bin/sh
# Starts rootwalk serve, asks it for each name twice with dig, and prints
# the cold and warm query times. Needs dig and a network that reaches the
# root servers. Usage: scripts/bench.sh [names file]
set -eu
names=${1:-scripts/names.txt}
port=5399
go build -o rootwalk ./cmd/rootwalk
./rootwalk serve -addr 127.0.0.1:$port 2>bench-serve.log &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
sleep 0.5

# Prints the query time in ms and the status, e.g. "319 NOERROR".
q() { dig @127.0.0.1 -p $port "$1" +tries=1 +time=15 | awk '/status:/ {sub(",", "", $6); s=$6} /Query time/ {t=$4} END {print t, s}'; }

colds=$(mktemp)
printf '%-28s %10s %10s %s\n' name cold_ms warm_ms status
while read -r name; do
	[ -z "$name" ] && continue
	set -- $(q "$name")
	cold=$1 st=$2
	set -- $(q "$name")
	printf '%-28s %10s %10s %s\n' "$name" "$cold" "$1" "$st"
	echo "$cold" >>"$colds"
done <"$names"
sort -n "$colds" | awk '{v[NR] = $1} END {
	m = NR % 2 ? v[(NR + 1) / 2] : (v[NR / 2] + v[NR / 2 + 1]) / 2
	printf "median cold %s ms over %d names, range %s to %s ms\n", m, NR, v[1], v[NR]
}'
rm -f "$colds"
kill $pid
wait $pid 2>/dev/null || true
tail -1 bench-serve.log
