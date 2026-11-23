"""Explicit product -> CPE mappings for fingerprints without a CPE.

Nmap often reports a product and version but no CPE, and correlation skips
those ports entirely. This table maps common nmap product strings to their
canonical CPE prefixes so version-based CVE correlation still works. It is
deliberately explicit: unknown products are skipped, never guessed, and a
wrong mapping fails benignly (no matches). Products with vendor churn in the
CPE dictionary list every candidate; each is queried and cached separately.
"""

from __future__ import annotations

import re

NMAP_PRODUCT_CPE: dict[str, list[str]] = {
    "openssh": ["cpe:/a:openbsd:openssh"],
    "dropbear ssh": ["cpe:/a:dropbear_ssh_project:dropbear_ssh"],
    "mysql": ["cpe:/a:mysql:mysql", "cpe:/a:oracle:mysql"],
    "mariadb": ["cpe:/a:mariadb:mariadb"],
    "postgresql": ["cpe:/a:postgresql:postgresql"],
    "redis": ["cpe:/a:redis:redis"],
    "mongodb": ["cpe:/a:mongodb:mongodb"],
    "memcached": ["cpe:/a:memcached:memcached"],
    "elasticsearch": ["cpe:/a:elastic:elasticsearch", "cpe:/a:elasticsearch:elasticsearch"],
    "samba": ["cpe:/a:samba:samba"],
    "proftpd": ["cpe:/a:proftpd:proftpd"],
    "vsftpd": ["cpe:/a:vsftpd_project:vsftpd"],
    "apache tomcat": ["cpe:/a:apache:tomcat"],
    "apache httpd": ["cpe:/a:apache:http_server"],
    "nginx": ["cpe:/a:nginx:nginx"],
    "lighttpd": ["cpe:/a:lighttpd:lighttpd"],
    "microsoft iis httpd": ["cpe:/a:microsoft:internet_information_services"],
    "jetty": ["cpe:/a:eclipse:jetty"],
    "node.js": ["cpe:/a:nodejs:node.js"],
    "openssl": ["cpe:/a:openssl:openssl"],
    "cups": ["cpe:/a:apple:cups"],
    "dovecot": ["cpe:/a:dovecot:dovecot"],
    "postfix": ["cpe:/a:postfix:postfix"],
    "exim": ["cpe:/a:exim:exim"],
    "squid": ["cpe:/a:squid-cache:squid"],
    "haproxy": ["cpe:/a:haproxy:haproxy"],
    "isc bind": ["cpe:/a:isc:bind"],
    "dnsmasq": ["cpe:/a:thekelleys:dnsmasq"],
    "unbound": ["cpe:/a:nlnetlabs:unbound"],
    "mosquitto": ["cpe:/a:eclipse:mosquitto"],
    "openvpn": ["cpe:/a:openvpn:openvpn"],
    "plex media server": ["cpe:/a:plex:plex_media_server"],
    "mikrotik routeros": ["cpe:/a:mikrotik:routeros"],
    "dd-wrt": ["cpe:/a:dd-wrt:dd-wrt"],
    "openwrt": ["cpe:/a:openwrt:openwrt"],
    "busybox": ["cpe:/a:busybox:busybox"],
    "libupnp": ["cpe:/a:libupnp_project:libupnp"],
    "miniupnpd": ["cpe:/a:miniupnp_project:miniupnpd"],
    "consul": ["cpe:/a:hashicorp:consul"],
    "etcd": ["cpe:/a:etcd:etcd"],
}

# A trailing letter is kept for OpenSSL-style versions (1.1.1k); OpenSSH patch
# suffixes (8.9p1) are stripped because the CPE dictionary versions the base.
_VERSION = re.compile(r"^\d+(?:\.\d+)+[a-z]?")


def cpes_for(product: str, version: str) -> list[str]:
    """CPE candidates for an nmap product/version pair, or [] when unmapped."""
    name = product.strip().lower()
    prefixes = NMAP_PRODUCT_CPE.get(name)
    if not prefixes:
        return []
    value = version.strip()
    if name == "openssh":
        value = re.sub(r"p\d+$", "", value)
    match = _VERSION.match(value)
    if not match:
        return []
    return [f"{prefix}:{match.group(0)}" for prefix in prefixes]
