from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Iterable, Mapping
from uuid import uuid4

from .approval import ApprovalWorkflow
from .contracts import AdapterContext, attribute_actor
from .store import LocalRecordStore
from .validation import find_local_paths


CHANGE_REQUEST_SCHEMA = "aine.control-plane.change-request.v1"
CHANGE_TYPES = ("feature", "fix", "requirement", "project_registration")
CHANGE_STATUSES = ("draft", "submitted", "approved", "rejected", "closed")
CHANGE_RISKS = ("low", "medium", "high")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _record_id(change_id: str, revision: int) -> str:
    return f"{change_id}:r{revision}"


def _list_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def validate_change_request(record: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if record.get("schema") != CHANGE_REQUEST_SCHEMA:
        errors.append("unsupported change request schema")
    if not isinstance(record.get("change_id"), str) or not record.get("change_id"):
        errors.append("change_id is required")
    if not isinstance(record.get("revision"), int) or record.get("revision", 0) < 1:
        errors.append("revision must be a positive integer")
    if record.get("change_type") not in CHANGE_TYPES:
        errors.append("change_type is unsupported")
    for field in ("title", "description", "requested_by", "created_at"):
        if not isinstance(record.get(field), str) or not record.get(field, "").strip():
            errors.append(f"{field} is required")
    if record.get("status") not in CHANGE_STATUSES:
        errors.append("status is unsupported")
    if record.get("risk") not in CHANGE_RISKS:
        errors.append("risk is unsupported")
    if not isinstance(record.get("scope"), Mapping):
        errors.append("scope must be an object")
    if not isinstance(record.get("acceptance_criteria"), list):
        errors.append("acceptance_criteria must be an array")
    if not isinstance(record.get("source_of_truth"), list):
        errors.append("source_of_truth must be an array")
    if not isinstance(record.get("evidence_ids"), list):
        errors.append("evidence_ids must be an array")
    if not isinstance(record.get("approval_required"), bool):
        errors.append("approval_required must be boolean")
    if record.get("read_only") is not True:
        errors.append("change request records must remain read_only")
    for path in find_local_paths(record, "change_request"):
        errors.append(f"runtime-local path is not allowed: {path}")
    return errors


def _outcome(
    context: AdapterContext,
    operation: str,
    status: str,
    *,
    result: Mapping[str, Any] | None = None,
    error_code: str | None = None,
    reasons: Iterable[str] = (),
) -> dict[str, Any]:
    outcome: dict[str, Any] = {
        "schema": "aine.control-plane.adapter-outcome.v1",
        "status": status,
        "adapter_id": "local.change-request-workflow",
        "operation": operation,
        "request_id": context.request_id,
        "read_only": context.read_only,
    }
    if result is not None:
        outcome["result"] = dict(result)
    if error_code:
        outcome["error_code"] = error_code
    reason_list = [str(reason) for reason in reasons if reason]
    if reason_list:
        outcome["reasons"] = reason_list
    return outcome


class ChangeRequestWorkflow:
    """Append-only proposal records for Control Plane-owned change intent."""

    def __init__(self, store: LocalRecordStore, approvals: ApprovalWorkflow | None = None) -> None:
        self.store = store
        self.approvals = approvals or ApprovalWorkflow(store)

    def create(self, request: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]:
        change_id = str(request.get("change_id") or f"change.{uuid4().hex}")
        scope = request.get("scope", {})
        normalized_scope = dict(scope) if isinstance(scope, Mapping) else {}
        record = {
            "schema": CHANGE_REQUEST_SCHEMA,
            "change_id": change_id,
            "revision": 1,
            "status": "draft",
            "change_type": str(request.get("change_type", "feature")),
            "title": str(request.get("title", "")),
            "description": str(request.get("description", "")),
            "scope": normalized_scope,
            **attribute_actor(request, context, "requested_by"),
            "owner": str(request.get("owner") or context.actor.get("id", "unknown")),
            "acceptance_criteria": _list_strings(request.get("acceptance_criteria", [])),
            "source_of_truth": _list_strings(request.get("source_of_truth", [])),
            "evidence_ids": _list_strings(request.get("evidence_ids", [])),
            "risk": str(request.get("risk", "medium")),
            "approval_required": bool(request.get("approval_required", True)),
            "created_at": str(request.get("created_at") or _now()),
            "read_only": True,
        }
        errors = validate_change_request(record)
        if errors:
            return _outcome(context, "create", "failure", error_code="invalid_change_request", reasons=errors)
        result = self.store.put(record, context, record_type="change_request", record_id=_record_id(change_id, 1))
        if result.get("status") == "success" and not result.get("result", {}).get("duplicate"):
            self.store.append_event("change_request.created", change_id, record, context)
        if result.get("status") != "success":
            return result
        response = dict(result)
        response["result"] = dict(result.get("result", {}))
        response["result"]["change_request"] = record
        return response

    def list(self) -> list[Mapping[str, Any]]:
        latest: dict[str, Mapping[str, Any]] = {}
        for record in self.store.list_records("change_request"):
            change_id = record.get("change_id")
            if not change_id:
                continue
            current = latest.get(str(change_id))
            if current is None or int(record.get("revision", 0)) > int(current.get("revision", 0)):
                latest[str(change_id)] = record
        return [latest[key] for key in sorted(latest)]

    def get(self, change_id: str) -> Mapping[str, Any] | None:
        return next((record for record in self.list() if record.get("change_id") == change_id), None)

    def submit(self, change_id: str, context: AdapterContext) -> Mapping[str, Any]:
        current = self.get(change_id)
        if current is None:
            return _outcome(context, "submit", "unknown", error_code="change_request_not_found", reasons=[change_id])
        if current.get("status") != "draft":
            return _outcome(
                context,
                "submit",
                "failure",
                error_code="invalid_change_request_transition",
                reasons=[f"change request is already {current.get('status')}"],
            )

        revision = int(current.get("revision", 0)) + 1
        approval_id = None
        if current.get("approval_required") is True:
            approval_id = "approval.change-request." + hashlib.sha256(f"{change_id}:r{revision}".encode("utf-8")).hexdigest()[:20]
        submitted = dict(current)
        submitted.update({
            "revision": revision,
            "status": "submitted",
            "submitted_at": _now(),
            "previous_revision": int(current.get("revision", 0)),
        })
        if approval_id:
            submitted["approval_id"] = approval_id
        errors = validate_change_request(submitted)
        if errors:
            return _outcome(context, "submit", "failure", error_code="invalid_change_request", reasons=errors)
        result = self.store.put(submitted, context, record_type="change_request", record_id=_record_id(change_id, revision))
        if result.get("status") != "success":
            return result
        self.store.append_event("change_request.submitted", change_id, submitted, context)

        approval: Mapping[str, Any] | None = None
        if approval_id:
            approval_request = {
                "approval_id": approval_id,
                "subject": {"change_id": change_id, "change_type": submitted["change_type"]},
                "scope": submitted["scope"],
                "requested_by": submitted["requested_by"],
                "required_approvals": 1,
                "required_roles": ["approver"],
                "evidence_ids": submitted["evidence_ids"],
            }
            self.approvals.create(approval_request, context)
            approval = self.approvals.get(approval_id)

        response = dict(result)
        response["result"] = dict(result.get("result", {}))
        response["result"]["change_request"] = self.get(change_id) or submitted
        if approval is not None:
            response["result"]["approval"] = approval
        return response
