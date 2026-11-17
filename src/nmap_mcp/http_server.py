#!/usr/bin/env python3
"""nmap-MCP mit vollem Optionsumfang über streamable-http (für Open WebUI).

Aufbauend auf AnimaTow/nmap-mcpserver (MIT). Einzige harte Grenze: das Ziel muss
im Prüfumfang (scope.json) liegen. Die nmap-OPTIONEN sind absichtlich frei —
voller nmap-Funktionsumfang, inkl. -sS/-O/--script.

Start:
  stdio:                 python3 -m nmap_mcp.http_server
  http (für Open WebUI): python3 -m nmap_mcp.http_server http 8791
Umgebung: MCP_BIND_HOST (Standard 0.0.0.0), NMAP_SCOPE (Pfad zu scope.json),
          NMAP_TIMEOUT (Sekunden, Standard 900).
"""
import asyncio
import os
import shutil
import subprocess
import sys
import time
import uuid

from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP

try:
    from nmap_mcp.scope_guard import lade_netze, ziel_erlaubt
except ImportError:  # flach ausgeführt (Container)
    from scope_guard import lade_netze, ziel_erlaubt

NMAP = shutil.which("nmap") or "/usr/bin/nmap"
TIMEOUT = int(os.environ.get("NMAP_TIMEOUT", "900"))
MAX_OUT = 60000

scan_results: dict[str, dict] = {}

_http = len(sys.argv) > 1 and sys.argv[1] == "http"
_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8791

mcp = FastMCP("nmap-full",
              host=os.environ.get("MCP_BIND_HOST", "0.0.0.0"),
              port=_port, stateless_http=True)


class ScanInput(BaseModel):
    target: str = Field(description="Ziel im Prüfumfang: IP, Hostname, CIDR oder Range (10.10.5.1-50). Mehrere mit Leerzeichen/Komma.")
    options: str = Field(default="-sV", description="Beliebige nmap-Optionen, z. B. '-sV -p 1-1000', '-A', '--script=banner'. Voller Umfang.")


class DetailInput(BaseModel):
    scan_id: str = Field(description="ID eines früheren Scans")


class EmptyInput(BaseModel):
    pass


def _run(target: str, options: str) -> str:
    cmd = [NMAP]
    if options:
        cmd += options.split()
    cmd += [t for t in target.replace(",", " ").split() if t]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return f"FEHLER: nmap-Zeitüberschreitung ({TIMEOUT} s). Befehl: {' '.join(cmd)}"
    out = p.stdout or ""
    if p.stderr:
        out += "\n[stderr]\n" + p.stderr
    if len(out) > MAX_OUT:
        out = out[:MAX_OUT] + "\n… (gekürzt)"
    return out or "(keine Ausgabe)"


@mcp.tool(name="run-nmap-scan", annotations={"title": "nmap (voller Umfang, nur eigene Netze)",
                                             "readOnlyHint": False, "destructiveHint": False, "openWorldHint": True})
async def run_nmap_scan(params: ScanInput) -> str:
    """Führt nmap mit beliebigen Optionen aus, aber nur gegen Ziele im Prüfumfang (scope.json).

    Ziele außerhalb der freigegebenen Netze werden abgelehnt. Die Optionen sind frei.
    """
    netze = lade_netze()
    if not ziel_erlaubt(params.target, netze):
        erlaubt = ", ".join(str(n) for n in netze)
        return f"ABGELEHNT: Ziel {params.target!r} liegt außerhalb des Prüfumfangs ({erlaubt})."
    text = await asyncio.to_thread(_run, params.target, params.options)
    sid = uuid.uuid4().hex[:12]
    scan_results[sid] = {"scan_id": sid, "target": params.target, "options": params.options,
                         "zeit": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()), "output": text}
    return f"scan_id: {sid}\n{text}"


@mcp.tool(name="get-scan-details", annotations={"title": "Scan-Details", "readOnlyHint": True, "destructiveHint": False})
async def get_scan_details(params: DetailInput) -> str:
    """Gibt die gespeicherte Ausgabe eines früheren Scans zurück."""
    d = scan_results.get(params.scan_id)
    if not d:
        return f"Kein Scan mit id {params.scan_id}."
    return f"Ziel {d['target']} | Optionen {d['options']} | {d['zeit']}\n{d['output']}"


@mcp.tool(name="list-all-scans", annotations={"title": "Scans auflisten", "readOnlyHint": True, "destructiveHint": False})
async def list_all_scans(params: EmptyInput) -> str:
    """Listet die scan_ids dieser Sitzung mit Ziel, Optionen und Zeit."""
    if not scan_results:
        return "Noch keine Scans."
    return "\n".join(f"{d['scan_id']}  {d['zeit']}  {d['target']}  {d['options']}" for d in scan_results.values())


@mcp.tool(name="nmap-scope", annotations={"title": "Prüfumfang anzeigen", "readOnlyHint": True, "destructiveHint": False})
async def nmap_scope(params: EmptyInput) -> str:
    """Zeigt die freigegebenen Netze (Prüfumfang) und ob nmap installiert ist."""
    netze = ", ".join(str(n) for n in lade_netze())
    return f"Prüfumfang (nur diese Netze): {netze}\nnmap: {NMAP}\nOptionen: frei (voller nmap-Umfang)"


if __name__ == "__main__":
    mcp.run(transport="streamable-http" if _http else "stdio")
