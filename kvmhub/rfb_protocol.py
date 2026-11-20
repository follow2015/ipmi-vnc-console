"""Per-brand console protocol strategy."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from .rfb_upstream import absorb_set_cookie, encode_auth_response, extract_ticket


class ConsoleProtocol(ABC):

    protocol_id: str = ""

    @abstractmethod
    def login_fields(self, username: str, password: str) -> dict[str, str]:
        pass

    @abstractmethod
    def extract_ticket(self, html: bytes) -> str:
        pass

    @abstractmethod
    def absorb_cookies(self, values: Iterable[str]) -> dict[str, str]:
        pass

    @abstractmethod
    def auth_response(self, ticket: str) -> bytes:
        pass

    @abstractmethod
    def security_type(self) -> int:
        pass

    @abstractmethod
    def client_init(self) -> bytes:
        pass

    @abstractmethod
    def message_profile(self, version: str | None) -> tuple[frozenset[int], dict[int, int]]:
        pass


class SupermicroProtocol(ConsoleProtocol):

    protocol_id = "supermicro-ikvm-html5"

    def login_fields(self, username: str, password: str) -> dict[str, str]:
        return {"name": username, "pwd": password}

    def extract_ticket(self, html: bytes) -> str:
        return extract_ticket(html)

    def absorb_cookies(self, values: Iterable[str]) -> dict[str, str]:
        return absorb_set_cookie(values)

    def auth_response(self, ticket: str) -> bytes:
        return encode_auth_response(ticket)

    def security_type(self) -> int:
        return 16

    def client_init(self) -> bytes:
        return b"\x01"

    def message_profile(self, version: str | None) -> tuple[frozenset[int], dict[int, int]]:
        from .passthrough import client_message_profile

        return client_message_profile(version)


PROTOCOLS: dict[str, type[ConsoleProtocol]] = {
    SupermicroProtocol.protocol_id: SupermicroProtocol,
}


def build_protocol(protocol_id: str | None) -> ConsoleProtocol:
    if protocol_id is None or protocol_id == "":
        return SupermicroProtocol()
    try:
        return PROTOCOLS[protocol_id]()
    except KeyError:
        raise ValueError(f"unknown_console_protocol:{protocol_id}") from None
