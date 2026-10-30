#!/bin/sh
# Bounded retention for one Suricata EVE file (run inside the Suricata container, see docker-compose.yml).
#
#   rotate-eve.sh FILE INTERVAL_SECONDS MAX_BYTES KEEP
#
# Classic logrotate scheme: rename FILE to FILE.<timestamp> (Suricata keeps writing to the renamed file, same inode,
# until it is told to reopen), then SIGHUP Suricata so it creates a fresh FILE. Rotates when the file is older than
# INTERVAL_SECONDS or bigger than MAX_BYTES, and keeps only the newest KEEP rotated files. The engine finds a rotated
# file by its inode, so alerts written between its last read and the rotation are still ingested exactly once.
f=$1 interval=$2 max=$3 keep=$4
last=$(date +%s)
while sleep 10; do
    now=$(date +%s)
    size=$(stat -c %s "$f" 2>/dev/null || echo 0)
    if [ "$size" -gt 0 ] && { [ "$size" -ge "$max" ] || [ $((now - last)) -ge "$interval" ]; }; then
        mv "$f" "$f.$(date +%Y%m%d%H%M%S)" && pkill -HUP -f '[s]uricata.*-c' || pkill -HUP -x Suricata-Main
        last=$now
    fi
    ls -1t "$f".* 2>/dev/null | tail -n +$((keep + 1)) | xargs -r rm -f
done
