from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Protocol


CONTRACT_VERSION = "aine.control-plane.contracts.v1"


class AdapterError(Exception):
    """Raised when an adapter cannot satisfy a contract without guessing."""


class CredentialProvider(Protocol):
    """Resolve a runtime credential reference without exposing its value."""

    def resolve(self, reference: str) -> str: ...


@dataclass(frozen=True)
class AdapterMetadata:
    adapter_id: str
    kind: str
    contract_version: str = CONTRACT_VERSION
    capabilities: tuple[str, ...] = ()
    read_only: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "kind": self.kind,
            "contract_version": self.contract_version,
            "capabilities": list(self.capabilities),
            "read_only": self.read_only,
        }


@dataclass(frozen=True)
class AdapterContext:
    request_id: str
    actor: Mapping[str, Any] = field(default_factory=dict)
    evidence_ids: tuple[str, ...] = ()
    read_only: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "actor": dict(self.actor),
            "evidence_ids": list(self.evidence_ids),
            "read_only": self.read_only,
        }



def attribute_actor(request: Mapping[str, Any], context: AdapterContext, field_name: str) -> dict[str, Any]:
    """Record who acted without letting the payload name the actor.

    ``field_name`` (``requested_by`` / ``reported_by``) keeps its v1 name but
    holds only the authenticated actor from the context, or ``"unknown"`` when
    the context carries none. The payload's value is kept beside it as
    ``claimed_actor`` and never copied into it. A row where the two differ is a
    finding; a null ``authenticated_actor`` marks a path that is not wired yet.
    """
    authenticated = context.actor.get("id") or context.actor.get("subject_id")
    claimed = request.get(field_name)
    return {
        field_name: str(authenticated) if authenticated else "unknown",
        "authenticated_actor": str(authenticated) if authenticated else None,
        "claimed_actor": str(claimed) if claimed else None,
    }

class EvidenceSinkAdapter(Protocol):
    """Persist or forward portable records without changing their meaning."""

    @property
    def metadata(self) -> AdapterMetadata: ...

    def put(self, record: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]: ...

    def get(self, record_id: str, context: AdapterContext) -> Mapping[str, Any] | None: ...

    def list(self, context: AdapterContext) -> Iterable[Mapping[str, Any]]: ...


class EvidenceSourceAdapter(Protocol):
    """Collect portable evidence from an external read-only source."""

    @property
    def metadata(self) -> AdapterMetadata: ...

    def collect(self, request: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]: ...


class IdentityAdapter(Protocol):
    """Resolve an external subject into portable policy attributes."""

    @property
    def metadata(self) -> AdapterMetadata: ...

    def resolve(self, subject_id: str, context: AdapterContext) -> Mapping[str, Any]: ...


class PortfolioViewAdapter(Protocol):
    """Render or publish a portable portfolio snapshot."""

    @property
    def metadata(self) -> AdapterMetadata: ...

    def publish(self, snapshot: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]: ...


class RetentionAdapter(Protocol):
    """Evaluate retention without deleting or silently mutating records."""

    @property
    def metadata(self) -> AdapterMetadata: ...

    def evaluate(self, records: Iterable[Mapping[str, Any]], policy: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]: ...
