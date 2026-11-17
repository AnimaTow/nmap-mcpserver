"""Ziel-Begrenzung (Prüfumfang) für den nmap-MCP.

Lässt Scans nur gegen die in scope.json freigegebenen Netze zu. Deckt die
nmap-Zielsyntax ab: einzelne IP, CIDR, Bindestrich-Range (10.10.5.1-50 oder
10.10.5.1-10.10.5.50), Komma-/Leerzeichen-Listen und Hostnamen (werden aufgelöst,
alle aufgelösten IPs müssen im Prüfumfang liegen). Unklares wird abgelehnt.

Der Prüfumfang ist die einzige harte Grenze; die nmap-Optionen bleiben frei.
"""
import ipaddress
import json
import os
import socket

HIER = os.path.dirname(os.path.abspath(__file__))


def lade_netze(pfad=None):
    pfad = pfad or os.environ.get("NMAP_SCOPE") or os.path.join(HIER, "scope.json")
    try:
        with open(pfad, encoding="utf-8") as f:
            d = json.load(f)
        netze = [ipaddress.ip_network(n, strict=False) for n in d.get("allow", [])]
        return netze or [ipaddress.ip_network("127.0.0.1/32")]
    except Exception:
        return [ipaddress.ip_network("127.0.0.1/32")]


def _ip_erlaubt(ip, netze):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in netze)


def _token_erlaubt(tok, netze):
    tok = tok.strip()
    if not tok:
        return True
    # CIDR
    if "/" in tok:
        try:
            return ipaddress.ip_network(tok, strict=False).subnet_of(_umfang_netz(netze, tok))
        except Exception:
            return False
    # Bindestrich-Range: a.b.c.d-e  oder  a.b.c.d-a.b.c.e
    if "-" in tok:
        links, rechts = tok.split("-", 1)
        links = links.strip()
        rechts = rechts.strip()
        try:
            start = ipaddress.ip_address(links)
        except ValueError:
            return False
        if "." in rechts:
            try:
                ende = ipaddress.ip_address(rechts)
            except ValueError:
                return False
        else:
            # nur letztes Oktett
            if not rechts.isdigit():
                return False
            teile = links.split(".")
            teile[-1] = rechts
            try:
                ende = ipaddress.ip_address(".".join(teile))
            except ValueError:
                return False
        if int(ende) < int(start):
            return False
        # Start und Ende müssen im selben erlaubten Netz liegen
        for n in netze:
            if start in n and ende in n:
                return True
        return False
    # einzelne IP?
    try:
        ipaddress.ip_address(tok)
        return _ip_erlaubt(tok, netze)
    except ValueError:
        pass
    # Hostname -> auflösen, ALLE IPs müssen erlaubt sein
    try:
        infos = socket.getaddrinfo(tok, None)
    except Exception:
        return False
    ips = {i[4][0] for i in infos}
    return bool(ips) and all(_ip_erlaubt(ip, netze) for ip in ips)


def _umfang_netz(netze, cidr):
    """Hilfs-Supernetz: das kleinste erlaubte Netz, das das CIDR enthalten könnte.
    subnet_of braucht ein Vergleichsnetz; wir prüfen gegen jedes erlaubte Netz."""
    netz = ipaddress.ip_network(cidr, strict=False)
    for n in netze:
        if netz.version == n.version and netz.subnet_of(n):
            return n
    # kein passendes -> gib ein Netz zurück, das die Prüfung scheitern lässt
    return ipaddress.ip_network("255.255.255.255/32")


def ziel_erlaubt(target, netze=None):
    """True nur, wenn JEDES Token des Ziels im Prüfumfang liegt."""
    netze = netze or lade_netze()
    tokens = [t for t in target.replace(",", " ").split() if t]
    if not tokens:
        return False
    return all(_token_erlaubt(t, netze) for t in tokens)


if __name__ == "__main__":
    # Beispielnetze aus RFC 5737 (Dokumentation), keine echten Adressen.
    netze = [ipaddress.ip_network(n) for n in
             ["127.0.0.1/32", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]]
    faelle = [
        ("192.0.2.108", True), ("198.51.100.5", True), ("203.0.113.20", True),
        ("127.0.0.1", True), ("192.0.2.0/24", True), ("192.0.2.1-50", True),
        ("192.0.2.1-192.0.2.50", True), ("192.0.2.1 198.51.100.2", True),
        ("192.0.2.1,203.0.113.2", True),
        ("8.8.8.8", False), ("192.0.3.1", False), ("192.0.2.0/23", False),
        ("192.0.2.250-192.0.3.5", False), ("10.0.0.0/8", False),
        ("example.com", False), ("192.0.2.1 8.8.8.8", False), ("", False),
    ]
    ok = 0
    for ziel, soll in faelle:
        ist = ziel_erlaubt(ziel, netze)
        mark = "OK " if ist == soll else "XX "
        ok += ist == soll
        print(f"{mark} {ziel!r:28} soll={soll} ist={ist}")
    print(f"{ok}/{len(faelle)} bestanden")
