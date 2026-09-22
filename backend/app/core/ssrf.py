import socket
import ipaddress
from urllib.parse import urlparse, urljoin
import httpx
from typing import Tuple, Optional, Any, Dict


class SSRFValidationError(ValueError):
    """Raised when a target URL violates SSRF security boundaries."""
    pass


# Cloud provider metadata IP addresses and hostnames
METADATA_IPS = {
    "169.254.169.254",   # AWS, GCP, Azure, OpenStack link-local metadata
    "169.254.170.2",     # AWS ECS container metadata
    "100.100.100.200",   # Alibaba Cloud metadata
    "fd00:ec2::254",     # AWS IPv6 metadata
}

BLOCKED_HOSTNAMES = {
    "instance-data",
    "metadata.google.internal",
    "metadata",
}

MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 1_048_576  # 1 MB maximum response size
DEFAULT_TIMEOUT_SECONDS = 5.0


def is_ip_blocked(ip_str: str, allow_local: bool = False) -> Tuple[bool, str]:
    """Check if an IP address belongs to prohibited network ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

    if ip_str in METADATA_IPS:
        return True, f"Access to cloud metadata service ({ip_str}) is prohibited"

    if ip.is_loopback:
        if allow_local:
            return False, ""
        return True, f"Loopback address ({ip_str}) is prohibited unless explicitly registered as local reference"

    if ip.is_private:
        if allow_local:
            return False, ""
        return True, f"Private RFC1918 address ({ip_str}) is prohibited"

    if ip.is_link_local:
        return True, f"Link-local address ({ip_str}) is prohibited"

    if ip.is_multicast:
        return True, f"Multicast address ({ip_str}) is prohibited"

    if ip.is_reserved:
        return True, f"Reserved address ({ip_str}) is prohibited"

    if ip.is_unspecified:
        return True, f"Unspecified address ({ip_str}) is prohibited"

    return False, ""


def validate_target_url(url: str, allow_local: bool = False) -> str:
    """Validate a target URL scheme, hostname, and resolved IP addresses against SSRF policies.
    
    Args:
        url: The target base URL string.
        allow_local: Whether loopback/private IPs are permitted (only for built-in reference targets).
        
    Returns:
        Cleaned URL string without trailing slashes.
        
    Raises:
        SSRFValidationError: If the URL fails scheme, hostname, or IP validation.
    """
    if not url or not isinstance(url, str):
        raise SSRFValidationError("Target URL must be a non-empty string.")

    cleaned = url.strip()
    try:
        parsed = urlparse(cleaned)
    except Exception as exc:
        raise SSRFValidationError(f"Malformed URL: {exc}") from exc

    # 1. Enforce HTTP/HTTPS scheme only
    if parsed.scheme.lower() not in ("http", "https"):
        raise SSRFValidationError(
            f"Prohibited URL scheme '{parsed.scheme}'. Only HTTP and HTTPS protocols are permitted."
        )

    # 2. Hostname validation
    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError("URL must include a valid hostname.")

    if hostname.lower() in BLOCKED_HOSTNAMES:
        raise SSRFValidationError(f"Access to prohibited hostname '{hostname}' is blocked.")

    # 3. Port validation
    port = parsed.port
    if port is not None and not (1 <= port <= 65535):
        raise SSRFValidationError(f"Invalid port number {port}.")

    # 4. Resolve DNS and validate all resolved IP addresses
    try:
        addr_info = socket.getaddrinfo(
            hostname,
            port or (443 if parsed.scheme.lower() == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise SSRFValidationError(f"DNS resolution failed for hostname '{hostname}': {exc}") from exc

    if not addr_info:
        raise SSRFValidationError(f"No IP addresses resolved for hostname '{hostname}'.")

    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        blocked, reason = is_ip_blocked(ip_str, allow_local=allow_local)
        if blocked:
            raise SSRFValidationError(reason)

    return cleaned.rstrip("/")


async def safe_http_get_json(
    url: str,
    allow_local: bool = False,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> Dict[str, Any]:
    """Fetch JSON from a target URL with SSRF validation, size caps, and secure redirect tracking."""
    current_url = validate_target_url(url, allow_local=allow_local)
    redirect_count = 0

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        while True:
            try:
                response = await client.get(current_url)
            except httpx.HTTPError as exc:
                raise SSRFValidationError(f"Target connection failed: {exc}") from exc

            # Check for redirect
            if response.status_code in (301, 302, 303, 307, 308):
                redirect_count += 1
                if redirect_count > MAX_REDIRECTS:
                    raise SSRFValidationError(f"Exceeded maximum allowed redirects ({MAX_REDIRECTS}).")
                location = response.headers.get("Location")
                if not location:
                    raise SSRFValidationError("Redirect response missing Location header.")
                # Resolve relative redirects
                next_url = urljoin(current_url, location)
                # Re-validate the redirect target against SSRF rules!
                current_url = validate_target_url(next_url, allow_local=allow_local)
                continue

            # Non-redirect response: check size cap
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_bytes:
                raise SSRFValidationError(
                    f"Target response size ({content_length} bytes) exceeds maximum permitted limit ({max_bytes} bytes)."
                )

            body = response.content
            if len(body) > max_bytes:
                raise SSRFValidationError(
                    f"Target response body ({len(body)} bytes) exceeds maximum permitted limit ({max_bytes} bytes)."
                )

            if response.status_code != 200:
                raise SSRFValidationError(
                    f"Target returned non-200 status code: {response.status_code}"
                )

            try:
                return response.json()
            except Exception as exc:
                raise SSRFValidationError(f"Target did not return valid JSON: {exc}") from exc
