"""Engagement safety controls — dependency-free, so they are always enforceable.

RedPrompt is for AUTHORIZED testing only. This module decides whether a given
target may be scanned, based on:

1. explicit authorization (the operator marked the target authorized), and
2. scope: the host must be on the allow-list, or (when public targets are
   blocked) resolve to a loopback / private / link-local address.

The default posture is *deny*: an unknown hostname that cannot be shown to be
local is refused rather than assumed safe. Callers use :func:`assert_target_allowed`
which raises :class:`SafetyViolation`; that exception is never caught by broad
handlers, so a scope breach can never be silently ignored.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class SafetyDecision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.allowed


def extract_host(url: str) -> str:
    """Return the lowercased host component of a URL (no port)."""
    parsed = urlparse(url if "://" in url else f"//{url}", scheme="http")
    host = parsed.hostname or ""
    return host.lower()


def classify_ip(host: str) -> str | None:
    """Classify an IP-literal host.

    Returns one of ``loopback`` / ``private`` / ``link_local`` / ``public``,
    or ``None`` if *host* is not an IP literal (i.e. it is a hostname).
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_private:
        return "private"
    return "public"


def is_local_target(url: str, allowed_hosts: list[str]) -> bool:
    """True if the URL's host is on the allow-list or a loopback/private IP."""
    host = extract_host(url)
    if not host:
        return False
    if host in {h.lower() for h in allowed_hosts}:
        return True
    kind = classify_ip(host)
    return kind in {"loopback", "private", "link_local"}


def evaluate_target(
    url: str,
    *,
    authorized: bool,
    require_authorization: bool,
    block_public_targets: bool,
    allowed_hosts: list[str],
) -> SafetyDecision:
    """Evaluate whether a target may be scanned. Pure and deterministic."""
    reasons: list[str] = []
    host = extract_host(url)

    if not host:
        return SafetyDecision(False, [f"cannot parse host from URL: {url!r}"])

    if require_authorization and not authorized:
        reasons.append("target is not marked authorized (safety.require_authorization)")

    if block_public_targets:
        allow = {h.lower() for h in allowed_hosts}
        if host in allow:
            pass  # explicitly in scope
        else:
            kind = classify_ip(host)
            if kind is None:
                reasons.append(
                    f"host {host!r} is not on the allow-list and cannot be verified as "
                    "local (safety.block_public_targets)"
                )
            elif kind == "public":
                reasons.append(
                    f"host {host!r} resolves to a public IP (safety.block_public_targets)"
                )

    return SafetyDecision(allowed=not reasons, reasons=reasons)


def assert_target_allowed(
    url: str,
    *,
    authorized: bool,
    require_authorization: bool,
    block_public_targets: bool,
    allowed_hosts: list[str],
) -> None:
    """Raise :class:`SafetyViolation` if the target is out of scope/unauthorized."""
    from redprompt.exceptions import SafetyViolation

    decision = evaluate_target(
        url,
        authorized=authorized,
        require_authorization=require_authorization,
        block_public_targets=block_public_targets,
        allowed_hosts=allowed_hosts,
    )
    if not decision.allowed:
        raise SafetyViolation("; ".join(decision.reasons))
