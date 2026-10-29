"""Hardware detection and scan profiles.

A Pi Zero and an x86 box should not use the same worker count or Nmap timing.
Profiles change only measured-cost knobs: how many scans run at once, Nmap's timing
template, and the default port range. Override anything with CVESCOUT_PROFILE,
CVESCOUT_WORKERS, CVESCOUT_NMAP_TIMING, or CVESCOUT_PORTS.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROFILES: dict[str, dict] = {
    # One worker is not a limitation on a Pi Zero, it is the correct setting: each Nmap
    # process costs 10-20 MB and the LAN, not the CPU, limits a home scan.
    "minimal": {"workers": 1, "timing": "-T3", "ports": "1-1024,8080,8443"},
    "balanced": {"workers": 2, "timing": "-T4", "ports": "1-1024,8080,8443"},
    "fast": {"workers": 4, "timing": "-T4", "ports": "1-8192,8443"},
}


@dataclass(frozen=True)
class Profile:
    name: str
    workers: int
    timing: str
    ports: str
    reason: str


def hardware() -> dict:
    model = ""
    try:
        model = Path("/proc/device-tree/model").read_bytes().decode("utf-8", "replace").strip("\x00").strip()
    except OSError:
        pass
    ram_mb = 0
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                ram_mb = int(line.split()[1]) // 1024
                break
    except (OSError, ValueError, IndexError):
        pass
    cores = os.cpu_count() or 1
    return {"model": model, "cores": cores, "ram_mb": ram_mb, "raspberry_pi": "raspberry pi" in model.lower()}


def _detected_name(cores: int, ram_mb: int) -> tuple[str, str]:
    if cores >= 4 and ram_mb >= 3800:
        return "fast", f"{cores} cores, {ram_mb} MB RAM"
    if cores >= 2 and ram_mb >= 900:
        return "balanced", f"{cores} cores, {ram_mb} MB RAM"
    return "minimal", f"{cores} core(s), {ram_mb or 'unknown'} MB RAM"


def choose() -> Profile:
    """Pick a profile from the environment or detected hardware."""
    detected = hardware()
    name, detail = _detected_name(detected["cores"], detected["ram_mb"])
    requested = os.getenv("CVESCOUT_PROFILE", "auto").strip().lower()
    if requested in PROFILES:
        name, detail = requested, f"CVESCOUT_PROFILE={requested}"
    values = PROFILES[name]
    model = detected["model"] or "unknown hardware"
    return Profile(
        name=name,
        workers=int(os.getenv("CVESCOUT_WORKERS", values["workers"])),
        timing=os.getenv("CVESCOUT_NMAP_TIMING", values["timing"]),
        ports=os.getenv("CVESCOUT_PORTS", values["ports"]),
        reason=f"{model}: {detail}",
    )
