from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Callable, Mapping

from .contracts import AdapterContext, attribute_actor
from .store import LocalRecordStore
from .validation import canonical_digest


APPROVAL_REQUEST_SCHEMA = "aine.control-plane.approval-request.v1"
APPROVAL_DECISION_SCHEMA = "aine.control-plane.approval-decision.v1"
APPROVAL_STATUSES = ("pending", "approved", "rejected", "expired")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class ApprovalWorkflow:
    """Append-only approval requests and decisions backed by LocalRecordStore."""

    def __init__(self, store: LocalRecordStore, clock: Callable[[], str] = _now) -> None:
        self.store = store
        self._clock = clock

    def create(self, request: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]:
        approval_id = str(request.get("approval_id", ""))
        if not approval_id:
            return self._failure(context, "invalid_approval_request", "approval_id is required")
        required_approvals = int(request.get("required_approvals", 1))
        if required_approvals < 1:
            return self._failure(context, "invalid_approval_request", "required_approvals must be positive")
        normalized = {
            "schema": APPROVAL_REQUEST_SCHEMA,
            "approval_id": approval_id,
            "subject": dict(request.get("subject", {})),
            "scope": dict(request.get("scope", {})),
            **attribute_actor(request, context, "requested_by"),
            "required_approvals": required_approvals,
            "required_roles": [str(value) for value in request.get("required_roles", [])],
            "evidence_ids": [str(value) for value in request.get("evidence_ids", [])],
            "expires_at": request.get("expires_at"),
            "requested_at": request.get("requested_at", self._clock()),
        }
        result = self.store.put(normalized, context, record_type="approval", record_id=approval_id)
        if result.get("status") == "success" and not result.get("result", {}).get("duplicate"):
            self.store.append_event("approval.requested", approval_id, normalized, context)
        if result.get("status") != "failure":
            response = dict(result)
            response["result"] = dict(result.get("result", {}))
            response["result"]["approval"] = self.get(approval_id) or normalized
            return response
        return result

    def decide(
        self,
        approval_id: str,
        decision: str,
        reason: str,
        context: AdapterContext,
    ) -> Mapping[str, Any]:
        request = self.store.get(approval_id)
        if request is None:
            return self._unknown(context, "approval_not_found", approval_id)
        if decision not in ("approve", "reject"):
            return self._failure(context, "invalid_decision", "decision must be approve or reject")

        current = self.get(approval_id)
        if current and current["status"] in ("approved", "rejected", "expired"):
            return self._failure(context, "approval_closed", f"approval is already {current['status']}")

        actor_id = str(context.actor.get("id") or context.actor.get("subject_id") or "unknown")
        required_roles = {str(value) for value in request.get("required_roles", [])}
        actor_roles = {str(value) for value in context.actor.get("roles", [])}
        if required_roles and not (required_roles & actor_roles):
            return self._failure(context, "approval_role_required", "actor does not have a required approval role")

        decision_id = "decision:" + sha256(
            f"{approval_id}:{actor_id}:{decision}:{reason}".encode("utf-8")
        ).hexdigest()[:24]
        decision_record = {
            "schema": APPROVAL_DECISION_SCHEMA,
            "decision_id": decision_id,
            "approval_id": approval_id,
            "actor_id": actor_id,
            "decision": decision,
            "reason": reason,
            "evidence_ids": list(context.evidence_ids),
            "decided_at": self._clock(),
        }
        result = self.store.put(decision_record, context, record_type="approval_decision", record_id=decision_id)
        if result.get("status") == "success" and not result.get("result", {}).get("duplicate"):
            self.store.append_event("approval.decided", approval_id, decision_record, context)
        if result.get("status") == "success":
            response = dict(result)
            response["result"] = dict(result.get("result", {}))
            response["result"]["approval"] = self.get(approval_id)
            return response
        return result

    def get(self, approval_id: str) -> Mapping[str, Any] | None:
        request = self.store.get(approval_id)
        if request is None:
            return None
        decisions = [
            record
            for record in self.store.list_records("approval_decision")
            if record.get("approval_id") == approval_id
        ]
        status = self._status(request, decisions)
        response = dict(request)
        response["status"] = status
        response["decisions"] = decisions
        return response

    def _status(self, request: Mapping[str, Any], decisions: list[Mapping[str, Any]]) -> str:
        if any(record.get("decision") == "reject" for record in decisions):
            return "rejected"
        required = int(request.get("required_approvals", 1))
        approvers = {str(record.get("actor_id")) for record in decisions if record.get("decision") == "approve"}
        if len(approvers) >= required:
            return "approved"
        expires_at = request.get("expires_at")
        if expires_at:
            try:
                if _parse_time(self._clock()) >= _parse_time(str(expires_at)):
                    return "expired"
            except ValueError:
                return "pending"
        return "pending"

    @staticmethod
    def _failure(context: AdapterContext, error_code: str, reason: str) -> Mapping[str, Any]:
        return {
            "schema": "aine.control-plane.adapter-outcome.v1",
            "status": "failure",
            "adapter_id": "local.approval-workflow",
            "operation": "approval",
            "request_id": context.request_id,
            "read_only": context.read_only,
            "error_code": error_code,
            "reasons": [reason],
        }

    @staticmethod
    def _unknown(context: AdapterContext, reason: str, approval_id: str) -> Mapping[str, Any]:
        return {
            "schema": "aine.control-plane.adapter-outcome.v1",
            "status": "unknown",
            "adapter_id": "local.approval-workflow",
            "operation": "approval",
            "request_id": context.request_id,
            "read_only": context.read_only,
            "result": {"approval_id": approval_id},
            "reasons": [reason],
        }
