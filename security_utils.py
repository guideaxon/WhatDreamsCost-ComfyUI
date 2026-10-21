import ipaddress
import os
from urllib.parse import urlsplit


def _host_without_port(host):
    """Strip the port from a Host/Origin authority, handling bracketed IPv6 literals."""
    try:
        return (urlsplit("//" + host).hostname or "").lower()
    except ValueError:
        return ""


def _is_allowed_host(host):
    """DNS-rebinding guard: only accept localhost, IP literals, or hosts listed in WDC_ALLOWED_HOSTS.

    A rebinding attacker needs a *hostname* that resolves to 127.0.0.1, so hostnames are refused
    unless the user explicitly opts in (comma-separated list, e.g. for a reverse proxy).
    """
    name = _host_without_port(host)
    if not name:
        return False
    if name == "localhost":
        return True
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        pass
    extra = {h.strip().lower() for h in os.environ.get("WDC_ALLOWED_HOSTS", "").split(",") if h.strip()}
    return name in extra


def is_same_origin_request(request):
    """Reject cross-origin browser requests (CSRF) and DNS-rebinding attempts against these routes."""
    if not _is_allowed_host(request.headers.get("Host", request.host)):
        return False

    fetch_site = request.headers.get("Sec-Fetch-Site")
    if fetch_site is not None:
        # "none" is a user-initiated navigation (address bar); never valid for state-changing methods.
        if fetch_site == "none":
            return request.method in ("GET", "HEAD")
        return fetch_site == "same-origin"

    origin = request.headers.get("Origin")
    if origin:
        return origin.split("://", 1)[-1] == request.host

    # No Origin/Sec-Fetch-Site header: non-browser local tools or very old browsers.
    return True


def safe_join(base_dir, user_path):
    """Resolve user_path under base_dir, returning None if the result is base_dir itself or escapes it."""
    if not user_path:
        return None
    base_real = os.path.normcase(os.path.realpath(base_dir))
    candidate_real = os.path.realpath(os.path.join(base_dir, user_path))
    try:
        inside = os.path.commonpath([base_real, os.path.normcase(candidate_real)]) == base_real
    except ValueError:  # different drives on Windows
        return None
    if not inside or os.path.normcase(candidate_real) == base_real:
        return None
    return candidate_real


def resolve_input_file(input_dir, rel_path, fallback_subdir="whatdreamscost"):
    """Locate an existing file for a workflow-supplied name, confined to input_dir.

    Tries input_dir/rel_path, then input_dir/fallback_subdir/<basename>. Returns None if neither
    exists or the name tries to escape input_dir (absolute path, "..", symlink out).
    """
    if not isinstance(rel_path, str) or not rel_path:
        return None
    rel_path = rel_path.replace("\\", "/")
    for base, name in (
        (input_dir, rel_path),
        (os.path.join(input_dir, fallback_subdir), os.path.basename(rel_path)),
    ):
        candidate = safe_join(base, name)
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def has_allowed_extension(path, extensions):
    """True if the fully resolved path (symlinks followed) ends with one of the allowed extensions."""
    return os.path.realpath(path).lower().endswith(tuple(extensions))
