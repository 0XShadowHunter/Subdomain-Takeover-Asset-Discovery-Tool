"""Domain input validation (AGENT_PLAN.md §3 task: input validation).

Rules: accept flexible user input (scheme/path/port are stripped), require a
valid bare domain, and reject IP addresses.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


class InvalidDomainError(ValueError):
    """Raised when user input is not a usable bare domain name."""


# label: 1-63 chars, letters/digits/hyphen, no leading or trailing hyphen.
_LABEL = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})+\.?$", re.IGNORECASE)


def normalize_domain(raw: object) -> str:
    """Clean user input into a bare lowercase domain, or raise InvalidDomainError.

    Accepts ``https://blog.example.com/path``, ``example.com:443``,
    ``EXAMPLE.com``. Rejects IPs (v4/v6), empty input, and anything that is
    not a syntactically valid domain name.
    """
    if raw is None:
        raise InvalidDomainError("Empty target")
    text = str(raw).strip().lower()
    if not text:
        raise InvalidDomainError("Empty target")

    # Strip scheme://user:pass@host:port/path -> host
    if "://" in text:
        try:
            text = urlparse(text).hostname or ""
        except ValueError as exc:
            raise InvalidDomainError(f"Malformed URL: {raw!r}") from exc
    else:
        text = text.split("/", 1)[0]
        if "@" in text:  # user:pass@host form without a scheme
            text = text.rsplit("@", 1)[-1]
    text = text.split(":")[0].rstrip(".").strip()
    if not text:
        raise InvalidDomainError(f"Empty target after cleanup: {raw!r}")

    # Reject IP literals (v4 and v6, including bracketed v6).
    candidate = text.strip("[]")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass  # not an IP address — good, continue validating as a domain
    else:
        raise InvalidDomainError(f"IP addresses are not allowed, got: {candidate}")

    if "." not in text:
        raise InvalidDomainError(f"Not a valid domain (no TLD): {text!r}")

    if not _DOMAIN_RE.match(text):
        raise InvalidDomainError(f"Not a valid domain name: {text!r}")

    if len(text) > 253:
        raise InvalidDomainError("Domain exceeds the 253-character limit")

    return text
