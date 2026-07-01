from requests.adapters import HTTPAdapter
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.contrib.socks import (
    SOCKSHTTPSConnectionPool, 
    SOCKSHTTPConnectionPool,
)

from .connector.default import (
    DoHHTTPConnection,
    DoHHTTPSConnection,
)

from .cachemanager import set_dns_cache_expire_time

from .connector.proxies import (
    SOCKSConnection,
    SOCKSHTTPSConnection
)

from .resolver import set_dns_provider, set_dns_provider_url

__all__ = ('DNSOverHTTPSAdapter',)

class DNSOverHTTPSAdapter(HTTPAdapter):
    """An DoH (DNS over HTTPS) adapter for :class:`requests.Session`

    Parameters
    -----------
    provider: :class:`str`
        A registered DoH provider, see :doc:`doh_providers`
    provider_url: :class:`str`
        Full URL / endpoint for a custom DoH provider, without the need to
        register it with :func:`add_dns_provider` first. May contain an IP
        address to skip DNS resolution of the provider itself.
    provider_host: :class:`str`
        The provider hostname. If given together with an IP based
        ``provider_url``, the connection is made to that IP (bypassing DNS)
        while TLS SNI and certificate verification use ``provider_host``.
    verify: Union[:class:`bool`, :class:`str`]
        TLS certificate verification for a ``provider_url`` provider. ``True``
        (the default) verifies against the default CA bundle, ``False`` disables
        verification, and a ``str`` specifies a path to a CA certificate file or
        directory.
    cache_expire_time: :class:`float`
        Set DNS cache expire time
    **kwargs
        These parameters will be passed to :class:`requests.adapters.HTTPAdapter`
    """
    def __init__(
        self,
        provider=None,
        provider_url=None,
        provider_host=None,
        cache_expire_time=None,
        verify=True,
        **kwargs
    ):
        if provider:
            set_dns_provider(provider)
        elif provider_url:
            set_dns_provider_url(provider_url, host=provider_host, verify=verify)

        if cache_expire_time:
            set_dns_cache_expire_time(cache_expire_time)

        super().__init__(**kwargs)

    def get_connection_with_tls_context(self, *args, **kwargs):
        conn = super().get_connection_with_tls_context(*args, **kwargs)
        if isinstance(conn, SOCKSHTTPSConnectionPool):
            conn.ConnectionCls = SOCKSHTTPSConnection
        elif isinstance(conn, SOCKSHTTPConnectionPool):
            conn.ConnectionCls = SOCKSConnection
        elif isinstance(conn, HTTPSConnectionPool):
            conn.ConnectionCls = DoHHTTPSConnection
        else:
            # HTTP type
            conn.ConnectionCls = DoHHTTPConnection
        return conn