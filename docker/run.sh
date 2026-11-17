#!/bin/sh
# nmap-MCP mit vollem Optionsumfang auf CT 115, nur lokal (127.0.0.1:8791).
# Ziel-Grenze = scope.json (eigene Netze). Optionen frei (voller nmap-Umfang).
# NET_RAW für SYN-/OS-Scans; sonst cap-drop ALL. scope.json read-only gemountet.
set -e
IMAGE=nmap-full:0.1
NAME=nmap-full
docker rm -f "$NAME" 2>/dev/null || true
docker run -d --name "$NAME" \
  --restart unless-stopped \
  -p 127.0.0.1:8791:8791 \
  --cap-drop ALL --cap-add NET_RAW \
  --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:rw,size=32m \
  --memory 512m \
  -v /opt/nmap-full/scope.json:/app/scope.json:ro \
  "$IMAGE"
echo "gestartet (Endpunkt http://127.0.0.1:8791/mcp)"
docker ps --filter "name=$NAME" --format "{{.Names}} {{.Status}} {{.Ports}}"
