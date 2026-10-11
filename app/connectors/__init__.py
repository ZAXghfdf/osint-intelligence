"""Connector registry — map source keys to connector instances."""
from __future__ import annotations

from .base import BaseConnector, ConnectorError, ConnectorResult
from .crtsh import CrtshConnector
from .dns_doh import DnsDohConnector
from .github import GithubConnector
from .gravatar import GravatarConnector
from .http_headers import HttpHeadersConnector
from .ip_info import IpInfoConnector
from .rdap import RdapConnector
from .wayback import WaybackConnector

CONNECTOR_CLASSES = [
    DnsDohConnector,
    CrtshConnector,
    RdapConnector,
    WaybackConnector,
    GithubConnector,
    IpInfoConnector,
    GravatarConnector,
    HttpHeadersConnector,
]

_registry: dict[str, BaseConnector] = {c.key: c() for c in CONNECTOR_CLASSES}


def get_connector(key: str) -> BaseConnector | None:
    return _registry.get(key)


def all_connectors() -> dict[str, BaseConnector]:
    return dict(_registry)


def connectors_for(indicator_type: str) -> list[BaseConnector]:
    return [c for c in _registry.values() if indicator_type in c.input_types]


__all__ = [
    "BaseConnector", "ConnectorError", "ConnectorResult",
    "get_connector", "all_connectors", "connectors_for",
]
