import httpx
from langchain_core.tools import tool

from soc_triage.config import MOCK_API_URL


def _lookup(ioc_type: str, value: str) -> dict:
    try:
        r = httpx.get(f"{MOCK_API_URL}/intel/{ioc_type}/{value}", timeout=10)
    except httpx.HTTPError as e:
        return {"error": f"Threat intel feed unreachable: {e}"}
    if r.status_code == 200:
        return r.json()
    return {"result": "no intel found", "indicator": value}


@tool
def lookup_ip(ip: str) -> dict:
    """Look up an IP address in the threat intelligence feed."""
    return _lookup("ip", ip)


@tool
def lookup_hash(file_hash: str) -> dict:
    """Look up a file hash (MD5/SHA) in the threat intelligence feed."""
    return _lookup("hash", file_hash)


@tool
def lookup_domain(domain: str) -> dict:
    """Look up a domain name in the threat intelligence feed."""
    return _lookup("domain", domain)


TOOLS = [lookup_ip, lookup_hash, lookup_domain]