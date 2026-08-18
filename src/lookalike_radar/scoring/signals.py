"""Collect the hard signals that tell a live phishing kit from a parked typo.

Turns "a lookalike exists" into evidence: is the page live, does it have a
login/password form, does the brand name appear on it, is it mail-capable
(MX/SPF/DMARC → BEC/credential-harvest by email), does it resolve at all, and
does it look like a parking placeholder. Read-only — it fetches the suspect page
and does DNS lookups, and takes no action.

Everything is best-effort: an unreachable domain is itself a signal (registered
but not stood up), and a missing optional dependency degrades one signal group
rather than failing the collection. The network seams (page fetch, DNS) are
injectable so this is fully testable offline.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_FETCH_TIMEOUT = 6
_DNS_TIMEOUT = 4.0
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
_PAGE_TEXT_BUDGET = 2500  # chars of visible text carried in the signal blob

_PASSWORD_INPUT_RE = re.compile(r"""<input[^>]+type=["']?password""", re.I)
_FORM_RE = re.compile(r"<form\b", re.I)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")

# Domain-parking / for-sale tells — a registrar holding page, not a real site.
_PARKING_MARKERS = (
    "this domain is for sale", "buy this domain", "domain for sale",
    "the domain may be for sale", "this domain may be for sale",
    "parked", "parking", "domain parking", "courtesy of", "coming soon",
    "under construction", "hugedomains", "sedoparking", "sedo.com",
    "godaddy.com/domainsearch", "bodis.com", "afternic", "dan.com",
    "domain has expired", "renew now",
)


def _strip_text(html: str) -> str:
    """Crude visible-text extraction (no bs4 dependency)."""
    html = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", html)
    text = _TAG_RE.sub(" ", html)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:_PAGE_TEXT_BUDGET]


def _looks_parked(page_sig: Dict[str, Any], page_text: str) -> Optional[bool]:
    """Parking/for-sale heuristic. None when the page couldn't be read."""
    if not page_sig.get("reachable"):
        return None
    haystack = " ".join(filter(None, [
        (page_text or "").lower(),
        (page_sig.get("title") or "").lower(),
        (page_sig.get("final_url") or "").lower(),
    ]))
    if any(m in haystack for m in _PARKING_MARKERS):
        return True
    # a reachable page with real content and a form is clearly not "parked"
    if page_sig.get("has_form") or page_sig.get("content_length", 0) > 1500:
        return False
    return False


# ---- default network implementations (lazy deps) --------------------------

def default_page_fetcher(domain: str) -> Tuple[Dict[str, Any], str]:
    """Fetch the suspect page (https then http) and extract page signals.

    Direct public-internet fetch, TLS verification disabled (phishing hosts
    routinely have broken/self-signed certs and that must not blind the scan).
    Needs the ``http`` extra.
    """
    sig: Dict[str, Any] = {
        "reachable": False, "status_code": None, "final_url": None,
        "redirected_offsite": False, "has_form": False, "has_password_input": False,
        "title": None, "content_length": 0, "error": None,
    }
    try:
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
        import warnings
        warnings.simplefilter("ignore", InsecureRequestWarning)
    except ImportError as exc:  # pragma: no cover
        raise ImportError("page fetching needs the 'http' extra: "
                          "pip install 'lookalike-radar[http]'") from exc

    headers = {"User-Agent": _UA, "Accept": "text/html,application/xhtml+xml"}
    page_text = ""
    for scheme in ("https", "http"):
        try:
            resp = requests.get(f"{scheme}://{domain}", timeout=_FETCH_TIMEOUT,
                                allow_redirects=True, headers=headers, verify=False)
        except Exception as e:  # noqa: BLE001 - unreachable is a signal, not an error
            sig["error"] = type(e).__name__
            continue
        body = resp.text or ""
        sig.update(reachable=True, status_code=resp.status_code, final_url=resp.url,
                   content_length=len(body), error=None,
                   has_form=bool(_FORM_RE.search(body)),
                   has_password_input=bool(_PASSWORD_INPUT_RE.search(body)))
        final_host = (resp.url.split("://", 1)[-1].split("/", 1)[0]).lower()
        sig["redirected_offsite"] = domain not in final_host
        m = _TITLE_RE.search(body)
        if m:
            sig["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:160]
        page_text = _strip_text(body)
        break
    return sig, page_text


def default_dns_resolver(domain: str) -> Dict[str, Any]:
    """Resolve A + MX and read SPF/DMARC TXT. Needs the ``dns`` extra."""
    out = {"has_a": False, "a_records": [], "has_mx": False, "mx_hosts": [],
           "has_spf": False, "has_dmarc": False, "error": None}
    try:
        import dns.resolver
    except ImportError:
        out["error"] = "dnspython_unavailable"
        return out
    r = dns.resolver.Resolver()
    r.lifetime = r.timeout = _DNS_TIMEOUT
    try:
        out["a_records"] = [str(a) for a in r.resolve(domain, "A")][:5]
        out["has_a"] = bool(out["a_records"])
    except Exception:
        pass
    try:
        answers = r.resolve(domain, "MX")
        out["has_mx"] = True
        out["mx_hosts"] = [str(a.exchange).rstrip(".") for a in answers][:5]
    except Exception:
        pass
    try:
        for rr in r.resolve(domain, "TXT"):
            txt = b"".join(rr.strings).decode("utf-8", "ignore") if hasattr(rr, "strings") else str(rr)
            if "v=spf1" in txt.lower():
                out["has_spf"] = True
    except Exception:
        pass
    try:
        for rr in r.resolve(f"_dmarc.{domain}", "TXT"):
            txt = b"".join(rr.strings).decode("utf-8", "ignore") if hasattr(rr, "strings") else str(rr)
            if "v=dmarc1" in txt.lower():
                out["has_dmarc"] = True
    except Exception:
        pass
    return out


# ---- collection -----------------------------------------------------------

def collect_signals(
    domain: str,
    brand: Optional[str] = None,
    *,
    page_fetcher: Optional[Callable[[str], Tuple[Dict[str, Any], str]]] = None,
    dns_resolver: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Collect page + DNS + parked + brand-on-page signals for ``domain``.

    Inject ``page_fetcher`` / ``dns_resolver`` (each a callable) to test offline
    or swap transports; both default to the real network implementations.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    page_fetcher = page_fetcher or default_page_fetcher
    dns_resolver = dns_resolver or default_dns_resolver

    try:
        page_sig, page_text = page_fetcher(domain)
    except Exception as e:  # noqa: BLE001
        logger.debug("page fetch failed for %s: %s", domain, e)
        page_sig, page_text = {"reachable": False, "error": type(e).__name__}, ""
    try:
        dns_sig = dns_resolver(domain)
    except Exception as e:  # noqa: BLE001
        logger.debug("dns resolve failed for %s: %s", domain, e)
        dns_sig = {"error": type(e).__name__}

    brand_in_page = None
    if brand and page_text:
        brand_in_page = brand.lower().replace(" ", "") in page_text.lower().replace(" ", "")

    return {
        "domain": domain,
        "brand": brand,
        "page": page_sig,
        "dns": dns_sig,
        "parked": _looks_parked(page_sig, page_text),
        "brand_in_page": brand_in_page,
        "page_text_excerpt": page_text,
    }
