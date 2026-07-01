from urllib.parse import urlsplit, urlunsplit

import httpx
import dns.inet
from dns.message import make_query
from dns.rdatatype import RdataType
from dns.query import https as query_https
from dns.rcode import Rcode

from .exceptions import (
    DNSQueryFailed,
    DoHProviderNotExist,
    NoDoHProvider
)

_resolver_session = None # type: httpx.Client
_available_providers = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "cloudflare-security": "https://security.cloudflare-dns.com/dns-query",
    "cloudflare-family": "https://family.cloudflare-dns.com/dns-query",
    "opendns": "https://doh.opendns.com/dns-query",
    "opendns-family": "https://doh.familyshield.opendns.com/dns-query",
    "adguard": "https://dns.adguard.com/dns-query",
    "adguard-family": "https://dns-family.adguard.com/dns-query",
    "adguard-unfiltered": "https://unfiltered.adguard-dns.com/dns-query",
    "quad9": "https://dns.quad9.net/dns-query",
    "quad9-unsecured": "https://dns10.quad9.net/dns-query",
    "google": "https://dns.google/dns-query"
}
# Default provider
_provider = _available_providers["cloudflare"]
# IP address used to connect to the active provider directly, bypassing DNS
# resolution of the provider hostname. ``None`` means resolve normally.
_provider_bootstrap_address = None
# TLS certificate verification for the active provider. See ``set_dns_provider_url``.
_provider_verify = True

__all__ = (
    'set_resolver_session', 'get_resolver_session',
    'set_dns_provider', 'set_dns_provider_url', 'get_dns_provider',
    'add_dns_provider', 'remove_dns_provider',
    'get_all_dns_provider', 'resolve_dns'
)

def set_resolver_session(session):
    """Set http session to resolve DNS

    Parameters
    -----------
    session: :class:`httpx.Client`
        An http session to resolve DNS

    Raises
    -------
    ValueError
        ``session`` parameter is not :class:`httpx.Client` instance    
    """
    global _resolver_session

    if not isinstance(session, httpx.Client):
        raise ValueError(f"`session` must be `httpx.Client`, {session.__class__.__name__}")
    
    _resolver_session = session

def get_resolver_session() -> httpx.Client:
    """
    Return
    -------
    httpx.Client
        Return an http session for DoH resolver
    """
    return _resolver_session

def set_dns_provider(provider):
    """Set a DoH provider, must be a valid DoH providers
    
    Parameters
    -----------
    provider: :class:`str`
        An valid DoH provider, see :doc:`doh_providers`

    Raises
    -------
    DoHProviderNotExist
        Invalid DoH provider
    """
    global _provider, _provider_bootstrap_address, _provider_verify

    if provider not in _available_providers.keys():
        raise DoHProviderNotExist(f"invalid DoH provider, must be one of '{list(_available_providers.keys())}'")

    _provider = _available_providers[provider]
    _provider_bootstrap_address = None
    _provider_verify = True

def _build_provider_url(url, host=None):
    """Return a ``(url, bootstrap_address)`` tuple for a DoH endpoint.

    If ``host`` is given and ``url`` points to an IP address, the returned URL
    will use ``host`` (so TLS SNI and certificate verification are done against
    the hostname) while the IP address is returned as the bootstrap address to
    connect to directly, bypassing DNS resolution of the provider hostname.
    """
    if host is None:
        return url, None

    parsed = urlsplit(url)
    bootstrap = None
    if parsed.hostname is not None and dns.inet.is_address(parsed.hostname):
        bootstrap = parsed.hostname

    netloc = host
    if parsed.port is not None:
        netloc = f"{host}:{parsed.port}"

    new_url = urlunsplit(
        (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
    )
    return new_url, bootstrap

def set_dns_provider_url(url, host=None, verify=True):
    """Set a custom DoH provider by its URL directly, without registering it
    with :func:`add_dns_provider` first.

    This makes it possible to skip DNS resolution entirely, including resolving
    the IP address of the DoH provider itself. Pass an IP address in ``url``
    together with ``host`` (the provider hostname) to connect straight to the IP
    while still verifying the TLS certificate against the hostname.

    For example:

    .. code-block:: python3

        from requests_doh import DNSOverHTTPSSession, set_dns_provider_url

        # Connect to Cloudflare by IP, verifying the certificate against
        # ``cloudflare-dns.com``
        set_dns_provider_url("https://104.16.249.249/dns-query", host="cloudflare-dns.com")

        session = DNSOverHTTPSSession()
        r = session.get("https://example.com")
        print(r.status_code)

    Parameters
    -----------
    url: :class:`str`
        Full URL / endpoint for the DoH provider. May contain an IP address.
    host: Optional[:class:`str`]
        The provider hostname. If given and ``url`` contains an IP address, the
        connection is made to that IP (bypassing DNS) while TLS SNI and
        certificate verification use ``host``.
    verify: Optional[Union[:class:`bool`, :class:`str`]]
        TLS certificate verification. ``True`` (the default) verifies against
        the default CA bundle, ``False`` disables verification, and a ``str``
        specifies a path to a CA certificate file or directory.
    """
    global _provider, _provider_bootstrap_address, _provider_verify

    _provider, _provider_bootstrap_address = _build_provider_url(url, host)
    _provider_verify = verify

def get_dns_provider():
    """
    Return
    -------
    str
        Return current DoH provider
    """
    return _provider

def add_dns_provider(name, address, switch=False):
    """Add a DoH provider
    
    Parameters
    -----------
    name: :class:`str`
        Name for DoH provider
    address: :class:`str`
        Full URL / endpoint for DoH provider
    switch: Optional[:class:`bool`]
        If ``True``, the DoH provider will automatically switch to 
        newly created DoH provider
    """
    _available_providers[name] = address

    if switch:
        set_dns_provider(name)

def remove_dns_provider(name, fallback=None):
    """Remove a DoH provider
    
    If parameter ``name`` is an active DoH provider, 
    :func:`get_dns_provider` will return ``None``. 
    You must set ``fallback`` parameter to one of available DoH providers 
    (``fallback`` and ``name`` parameters cannot be same value) 
    or you can call :func:`set_dns_provider` after calling this function
    in order to get DoH working

    For example:

    .. code-block:: python3

        from requests_doh import DNSOverHTTPSSession, add_dns_provider, remove_dns_provider

        # Add a custom DNS and set it to active
        add_dns_provider("another-dns", "https://another-dns.example.com/dns-query", switch=True)

        # At this point, the session is still working
        session = DNSOverHTTPSSession("another-dns")
        r = session.get("https://example.com")
        print(r.status_code)

        # Let's try to remove the newly created DNS
        remove_dns_provider("another-dns", fallback="cloudflare")

        # Or we can call `set_dns_provider()`
        # if we didn't set `fallback` parameter
        # set_dns_provider("cloudflare")

        # At this point DoH provider "another-dns" is removed 
        # and "cloudflare" is set to active DoH provider
        # the session is still working
        r = session.get("https://google.com")

    But what will happend if we didn't add ``fallback`` parameter or didn't call :func:`set_dns_provider()` ?
    Well error will occurred, take a look at this example:

    .. code-block:: python3

        from requests_doh import DNSOverHTTPSSession, add_dns_provider, remove_dns_provider

        # Add a custom DNS and set it to active
        add_dns_provider("another-dns", "https://another-dns.example.com/dns-query", switch=True)

        # At this point, the session is still working
        session = DNSOverHTTPSSession("another-dns")
        r = session.get("https://example.com")
        print(r.status_code)

        # Let's try to remove the newly created DNS
        remove_dns_provider("another-dns")

        # If we send request to same URL, it would still working
        r = session.get("https://example.com")
        print(r.status_code)

        # An error occurred when we send to another URL
        # Because we didn't set ``falback`` parameter in `remove_dns_provider()`
        # (or calling function `set_dns_provider()`)
        # `get_dns_provider()` will return ``None`` and thus resolving DNS will be failed
        # Because there is no valid endpoint where we wanna resolve DNS of the host
        r = session.get("https://google.com")

    Parameters
    -----------
    name: :class:`str`
        DoH provider that want to remove
    fallback: :class:`str`
        Set a fallback DoH provider

    Raises
    -------
    DoHProviderNotExist
        DoH provider is not exist in list of available DoH providers
    """
    global _provider, _provider_bootstrap_address, _provider_verify

    try:
        _available_providers.pop(name)
    except KeyError:
        raise DoHProviderNotExist(
            "DoH provider is not exist in list of available DoH providers"
        )

    if fallback:
        set_dns_provider(fallback)
    else:
        _provider = None
        _provider_bootstrap_address = None
        _provider_verify = True

def get_all_dns_provider():
    """
    Return
    -------
    tuple[str]
        Return all available DoH providers
    """
    return tuple(_available_providers.keys())

def _resolve(session, doh_endpoint, host, rdatatype, bootstrap_address=None, verify=True):
    req_message = make_query(host, rdatatype)
    res_message = query_https(
        req_message,
        doh_endpoint,
        session=session,
        bootstrap_address=bootstrap_address,
        verify=verify,
    )
    rcode = Rcode(res_message.rcode())
    if rcode != Rcode.NOERROR:
        raise DNSQueryFailed(f"Failed to query DNS {rdatatype.name} from host '{host}' (rcode = {rcode.name}")

    answers = res_message.resolve_chaining().answer
    if answers is None:
        return None

    return tuple(str(i) for i in answers)

def resolve_dns(host):
    if _provider is None:
        raise NoDoHProvider("There is no active DoH provider")

    if _provider_bootstrap_address is not None or _provider_verify is not True:
        # dnspython ignores ``bootstrap_address`` and ``verify`` when an existing
        # session is passed in, so let it build its own client with those applied.
        session = None
    else:
        session = get_resolver_session()

        if session is None:
            session = httpx.Client()
            set_resolver_session(session)

    answers = set()

    # Reuse is good
    def query(rdatatype):
        return _resolve(
            session,
            _provider,
            host,
            rdatatype,
            bootstrap_address=_provider_bootstrap_address,
            verify=_provider_verify,
        )

    # Query A type
    A_ANSWERS = query(RdataType.A)
    if A_ANSWERS is not None:
        answers.update(A_ANSWERS)

    # Query AAAA type
    AAAA_ANSWERS = query(RdataType.AAAA)
    if AAAA_ANSWERS is not None:
        answers.update(AAAA_ANSWERS)

    if not answers:
        raise DNSQueryFailed(
            f"DNS server {_provider} returned empty results from host '{host}'"
        )

    return list(answers)