from __future__ import annotations

import fcntl
import ipaddress
import os
import socket
import struct
from pathlib import Path


def _default_interface() -> str | None:
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) > 1 and fields[1] == "00000000":
                return fields[0]
    except OSError:
        return None
    return None


def detect_network() -> str | None:
    interface = _default_interface()
    if not interface:
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", interface.encode()[:15])
        address = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915, packed)[20:24])
        netmask = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x891B, packed)[20:24])
        return str(ipaddress.ip_network(f"{address}/{netmask}", strict=False))
    except OSError:
        return None
    finally:
        sock.close()


def configured_networks() -> list[ipaddress.IPv4Network]:
    raw = os.getenv("CVESCOUT_NETWORKS") or detect_network() or ""
    networks = []
    for value in raw.split(","):
        value = value.strip()
        if value:
            network = ipaddress.ip_network(value, strict=False)
            if network.version != 4:
                raise ValueError("Only IPv4 networks are supported")
            networks.append(network)
    return networks


def load_or_create_secret(instance_path: str) -> str:
    path = Path(os.getenv("CVESCOUT_SECRET_FILE", Path(instance_path) / "secret_key"))
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_text().strip()
    secret = os.urandom(32).hex()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(secret)
    return secret
