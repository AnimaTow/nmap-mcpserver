FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "mcp>=1.2,<2"

WORKDIR /app
# flach kopieren (kein Paket-Import -> kein libnmap nötig)
COPY src/nmap_mcp/http_server.py src/nmap_mcp/scope_guard.py src/nmap_mcp/scope.json /app/

EXPOSE 8791
ENV MCP_BIND_HOST=0.0.0.0
CMD ["python3", "http_server.py", "http", "8791"]
