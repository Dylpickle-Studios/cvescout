from __future__ import annotations

import ipaddress
import subprocess
import xml.etree.ElementTree as ET

from flask import current_app

from .db import get_db, now


class ScanError(RuntimeError):
    pass


def _run_nmap(arguments: list[str], timeout: int | None = None) -> ET.Element:
    command = [current_app.config["NMAP"], *arguments, "-oX", "-"]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout or current_app.config["SCAN_TIMEOUT"],
            check=False,
        )
    except FileNotFoundError as exc:
        raise ScanError("nmap is not installed or CVESCOUT_NMAP is wrong") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError("nmap scan timed out") from exc
    if result.returncode != 0:
        raise ScanError(result.stderr.strip() or f"nmap exited with {result.returncode}")
    try:
        return ET.fromstring(result.stdout)
    except ET.ParseError as exc:
        raise ScanError("nmap returned invalid XML") from exc


def allowed_networks() -> list[ipaddress.IPv4Network]:
    networks = current_app.config["NETWORKS"]
    if not networks:
        raise ScanError("No scan network configured; set CVESCOUT_NETWORKS")
    max_hosts = current_app.config["MAX_NETWORK_HOSTS"]
    for network in networks:
        if network.num_addresses > max_hosts:
            raise ScanError(f"{network} has {network.num_addresses} addresses; limit is {max_hosts}")
    return networks


def validate_target(address: str) -> str:
    try:
        target = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ScanError("Invalid device address") from exc
    if target.version != 4 or not any(target in network for network in allowed_networks()):
        raise ScanError(f"Target {target} is outside configured networks")
    return str(target)


def _host_record(host: ET.Element) -> dict | None:
    status = host.find("status")
    ipv4 = next((a for a in host.findall("address") if a.get("addrtype") == "ipv4"), None)
    if ipv4 is None:
        return None
    mac = next((a for a in host.findall("address") if a.get("addrtype") == "mac"), None)
    hostname = host.find("hostnames/hostname")
    return {
        "address": ipv4.get("addr", ""),
        "hostname": hostname.get("name", "") if hostname is not None else "",
        "mac": mac.get("addr", "") if mac is not None else "",
        "vendor": mac.get("vendor", "") if mac is not None else "",
        "status": status.get("state", "unknown") if status is not None else "unknown",
    }


def discover_network() -> int:
    networks = allowed_networks()
    root = _run_nmap(["-sn", *map(str, networks)])
    found = [record for host in root.findall("host") if (record := _host_record(host))]
    db = get_db()
    timestamp = now()
    db.execute("UPDATE devices SET status='down'")
    for device in found:
        db.execute(
            "INSERT INTO devices(address,hostname,mac,vendor,status,last_seen) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(address) DO UPDATE SET hostname=excluded.hostname, mac=excluded.mac, "
            "vendor=excluded.vendor, status=excluded.status, last_seen=excluded.last_seen",
            (*device.values(), timestamp),
        )
    db.commit()
    return sum(device["status"] == "up" for device in found)


def refresh_devices() -> int:
    db = get_db()
    addresses = [row["address"] for row in db.execute("SELECT address FROM devices").fetchall()]
    if not addresses:
        return 0
    targets = [validate_target(address) for address in addresses]
    root = _run_nmap(["-sn", *targets])
    found = {record["address"]: record for host in root.findall("host") if (record := _host_record(host))}
    timestamp = now()
    for address in addresses:
        device = found.get(address)
        if device:
            db.execute(
                "UPDATE devices SET hostname=?,mac=?,vendor=?,status=?,last_seen=? WHERE address=?",
                (device["hostname"], device["mac"], device["vendor"], device["status"], timestamp, address),
            )
        else:
            db.execute("UPDATE devices SET status='down' WHERE address=?", (address,))
    db.commit()
    return sum(device["status"] == "up" for device in found.values())


def _port_records(root: ET.Element) -> list[dict]:
    records = []
    for port in root.findall("host/ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port.find("service")
        cpes = [node.text for node in port.findall("service/cpe") if node.text]
        records.append(
            {
                "port": int(port.get("portid", "0")),
                "protocol": port.get("protocol", "tcp"),
                "state": "open",
                "service": service.get("name", "") if service is not None else "",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
                "extra_info": service.get("extrainfo", "") if service is not None else "",
                "cpe": "\n".join(cpes),
            }
        )
    return records


def scan_device_ports(device_id: int) -> int:
    db = get_db()
    device = db.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if not device:
        raise ScanError("Device not found")
    address = validate_target(device["address"])
    root = _run_nmap(["-Pn", "-sV", "--version-light", current_app.config["NMAP_TIMING"], "-p", current_app.config["PORTS"], address])
    ports = _port_records(root)
    timestamp = now()
    seen = set()
    for port in ports:
        seen.add((port["port"], port["protocol"]))
        db.execute(
            "INSERT INTO ports(device_id,port,protocol,state,service,product,version,extra_info,cpe,last_seen) "
            "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id,port,protocol) DO UPDATE SET "
            "state=excluded.state,service=excluded.service,product=excluded.product,version=excluded.version," 
            "extra_info=excluded.extra_info,cpe=excluded.cpe,last_seen=excluded.last_seen",
            (device_id, *port.values(), timestamp),
        )
    existing = db.execute("SELECT id,port,protocol FROM ports WHERE device_id=?", (device_id,)).fetchall()
    for old in existing:
        if (old["port"], old["protocol"]) not in seen:
            db.execute("DELETE FROM ports WHERE id=?", (old["id"],))
    db.execute("UPDATE devices SET status='up',last_seen=? WHERE id=?", (timestamp, device_id))
    db.commit()
    return len(ports)


def scan_all_ports(device_id: int | None = None) -> tuple[int, int]:
    db = get_db()
    if device_id:
        ids = [device_id]
    else:
        ids = [row["id"] for row in db.execute("SELECT id FROM devices WHERE status='up' ORDER BY address")]
    total = 0
    for current_id in ids:
        total += scan_device_ports(current_id)
    return len(ids), total
