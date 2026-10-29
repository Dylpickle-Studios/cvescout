from __future__ import annotations

import re
import ssl
from datetime import UTC, datetime


def _finding(
    key: str,
    severity: str,
    category: str,
    title: str,
    detail: str,
    evidence: str = "",
    remediation: str = "",
) -> dict:
    return {
        "finding_key": key,
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail,
        "evidence": evidence,
        "remediation": remediation,
    }


def detect_provider(records: dict, https: dict) -> tuple[str, bool]:
    headers = https.get("headers", {})
    cname = " ".join(records.get("CNAME", [])).lower()
    nameservers = " ".join(records.get("NS", [])).lower()
    server = headers.get("server", "").lower()
    via = headers.get("via", "").lower()
    if "cf-ray" in headers or server == "cloudflare":
        return "Cloudflare", True
    if "x-amz-cf-id" in headers or "cloudfront" in cname or "cloudfront" in via:
        return "Amazon CloudFront", True
    if "x-served-by" in headers or "fastly" in cname:
        return "Fastly", True
    if "x-akamai-transformed" in headers or any(value in cname for value in ("akamaiedge", "edgesuite")):
        return "Akamai", True
    if "x-azure-ref" in headers or any(value in cname for value in ("azurefd", "trafficmanager")):
        return "Azure Front Door", True
    if "x-vercel-id" in headers or "vercel-dns" in cname:
        return "Vercel", True
    if "x-nf-request-id" in headers or "netlify" in cname:
        return "Netlify", True
    if "cloudflare" in nameservers:
        return "Cloudflare DNS (proxy not confirmed)", False
    return "Direct or unknown", False


def _edge_findings(provider: str, edge_confirmed: bool) -> list[dict]:
    findings = [
        _finding(
            "edge.provider",
            "info",
            "edge",
            f"Public edge: {provider}",
            "Provider detection uses public DNS names and response headers.",
        )
    ]
    if provider.startswith("Cloudflare DNS") and not edge_confirmed:
        findings.append(
            _finding(
                "edge.cloudflare_unconfirmed",
                "low",
                "edge",
                "Cloudflare proxy not confirmed",
                "Cloudflare authoritative DNS was detected, but public HTTP evidence did not confirm proxying.",
                remediation="If this hostname should be protected, confirm its DNS record is proxied and origin access is restricted.",
            )
        )
    return findings


def _email_findings(records: dict) -> list[dict]:
    findings = []
    mx = records.get("MX", [])
    txt = records.get("TXT", [])
    spf = next((value for value in txt if value.lower().startswith("v=spf1")), "")
    dmarc = next((value for value in records.get("DMARC", []) if value.lower().startswith("v=dmarc1")), "")
    if mx and not spf:
        findings.append(
            _finding(
                "email.spf_missing",
                "medium",
                "email",
                "SPF record missing",
                "Domain receives email but no SPF policy was found.",
                remediation="Publish a least-privilege SPF TXT record for authorized senders.",
            )
        )
    if spf and any(token.lower() in {"all", "+all"} for token in spf.split()):
        findings.append(
            _finding(
                "email.spf_allow_all",
                "high",
                "email",
                "SPF permits every sender",
                "An all or +all mechanism allows any server to pass SPF.",
                evidence=spf,
                remediation="Replace allow-all with authorized senders and a softfail or fail policy.",
            )
        )
    if mx and not dmarc:
        findings.append(
            _finding(
                "email.dmarc_missing",
                "medium",
                "email",
                "DMARC record missing",
                "Domain receives email but no DMARC policy was found at the scanned hostname.",
                remediation="Publish a DMARC record and monitor reports before enforcing quarantine or reject.",
            )
        )
    elif dmarc and re.search(r"(?:^|;)\s*p=none(?:;|$)", dmarc, re.IGNORECASE):
        findings.append(
            _finding(
                "email.dmarc_monitor_only",
                "low",
                "email",
                "DMARC is monitoring only",
                "DMARC p=none gathers reports but does not request enforcement.",
                evidence=dmarc,
                remediation="Move toward quarantine or reject after validating legitimate mail flows.",
            )
        )
    return findings


def _certificate_findings(https: dict) -> list[dict]:
    if not https.get("ok"):
        return [
            _finding(
                "tls.unavailable",
                "high",
                "tls",
                "Trusted HTTPS connection failed",
                "Public clients may receive a connection or certificate validation failure.",
                evidence=https.get("error", ""),
                remediation="Install a valid certificate and make HTTPS reachable through the intended edge provider.",
            )
        ]
    findings = []
    tls_version = https.get("tls_version", "")
    if tls_version not in {"TLSv1.2", "TLSv1.3"}:
        findings.append(
            _finding(
                "tls.legacy_version",
                "high",
                "tls",
                "Legacy TLS negotiated",
                f"Scanner negotiated {tls_version or 'an unknown TLS version'}.",
                remediation="Require TLS 1.2 or newer at the edge and origin.",
            )
        )
    expires = https.get("certificate_expires")
    if not expires:
        return findings
    expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(expires), UTC)
    days = (expiry - datetime.now(UTC)).days
    if days < 14:
        findings.append(
            _finding(
                "tls.certificate_expiry",
                "high",
                "tls",
                "Certificate expires soon",
                f"Certificate expires in {days} days.",
                evidence=expiry.isoformat(),
                remediation="Renew certificate and verify automated renewal.",
            )
        )
    elif days < 30:
        findings.append(
            _finding(
                "tls.certificate_expiry",
                "medium",
                "tls",
                "Certificate renewal is approaching",
                f"Certificate expires in {days} days.",
                evidence=expiry.isoformat(),
                remediation="Confirm automated renewal before expiry.",
            )
        )
    return findings


def _header_findings(https: dict) -> list[dict]:
    if not https.get("ok"):
        return []
    findings = []
    headers = https.get("headers", {})
    hsts = headers.get("strict-transport-security", "")
    if not hsts:
        findings.append(
            _finding(
                "http.hsts_missing",
                "medium",
                "headers",
                "HSTS header missing",
                "HTTPS responses do not instruct browsers to remain on HTTPS.",
                remediation="Add Strict-Transport-Security after confirming all subresources support HTTPS.",
            )
        )
    else:
        match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if not match or int(match.group(1)) < 15_552_000:
            findings.append(
                _finding(
                    "http.hsts_short",
                    "low",
                    "headers",
                    "HSTS duration is short",
                    "HSTS max-age is below 180 days.",
                    evidence=hsts,
                    remediation="Increase max-age after validating HTTPS coverage.",
                )
            )
    csp = headers.get("content-security-policy", "")
    if not csp:
        findings.append(
            _finding(
                "http.csp_missing",
                "low",
                "headers",
                "Content Security Policy missing",
                "No Content-Security-Policy header was observed on the root response.",
                remediation="Deploy a tested CSP appropriate for the application.",
            )
        )
    if "frame-ancestors" not in csp.lower() and "x-frame-options" not in headers:
        findings.append(
            _finding(
                "http.frame_protection_missing",
                "low",
                "headers",
                "Clickjacking protection missing",
                "Neither CSP frame-ancestors nor X-Frame-Options was observed.",
                remediation="Set CSP frame-ancestors or X-Frame-Options.",
            )
        )
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(
            _finding(
                "http.nosniff_missing",
                "low",
                "headers",
                "MIME sniffing protection missing",
                "X-Content-Type-Options: nosniff was not observed.",
                remediation="Add X-Content-Type-Options: nosniff.",
            )
        )
    if "referrer-policy" not in headers:
        findings.append(
            _finding(
                "http.referrer_policy_missing",
                "low",
                "headers",
                "Referrer Policy missing",
                "No Referrer-Policy header was observed.",
                remediation="Set a policy such as strict-origin-when-cross-origin.",
            )
        )
    server = headers.get("server", "")
    if re.search(r"\d", server):
        findings.append(
            _finding(
                "http.server_version",
                "low",
                "headers",
                "Server version disclosed",
                "The Server header appears to include version information.",
                evidence=server,
                remediation="Remove unnecessary server version details where practical.",
            )
        )
    return findings


def _cookie_findings(https: dict) -> list[dict]:
    findings = []
    for index, cookie in enumerate(https.get("set_cookies", [])):
        name = cookie.split("=", 1)[0].strip() or f"cookie {index + 1}"
        attributes = {part.strip().split("=", 1)[0].lower() for part in cookie.split(";")[1:]}
        if "secure" not in attributes:
            findings.append(
                _finding(
                    f"cookie.{index}.secure_missing",
                    "medium",
                    "cookies",
                    f"Cookie {name} lacks Secure",
                    "Cookie could be sent over an unencrypted connection.",
                    remediation="Add the Secure attribute to cookies set over HTTPS.",
                )
            )
        if "httponly" not in attributes:
            findings.append(
                _finding(
                    f"cookie.{index}.httponly_missing",
                    "low",
                    "cookies",
                    f"Cookie {name} lacks HttpOnly",
                    "Client-side scripts can read this cookie.",
                    remediation="Add HttpOnly when JavaScript access is not required.",
                )
            )
    return findings


def _transport_findings(http: dict) -> list[dict]:
    if not http.get("ok"):
        return []
    location = http.get("headers", {}).get("location", "")
    if http.get("status") in {301, 302, 307, 308} and location.lower().startswith("https://"):
        return []
    return [
        _finding(
            "http.redirect_missing",
            "medium",
            "transport",
            "HTTP does not redirect to HTTPS",
            "Port 80 returned a response without a direct HTTPS redirect.",
            evidence=f"HTTP {http.get('status')} Location: {location or '(none)'}",
            remediation="Redirect every HTTP request to the canonical HTTPS URL.",
        )
    ]


def analyze_domain(records: dict, https: dict, http: dict) -> tuple[str, list[dict]]:
    provider, edge_confirmed = detect_provider(records, https)
    findings = _edge_findings(provider, edge_confirmed)
    findings.extend(_email_findings(records))
    findings.extend(_certificate_findings(https))
    findings.extend(_header_findings(https))
    findings.extend(_cookie_findings(https))
    findings.extend(_transport_findings(http))
    return provider, findings
