from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Callable, Iterable, Mapping
from uuid import uuid4

from .approval import ApprovalWorkflow
from .contracts import AdapterContext, attribute_actor
from .store import LocalRecordStore
from .validation import find_local_paths


REMEDIATION_PLAN_SCHEMA = "aine.control-plane.remediation-plan.v1"
EXECUTION_REQUEST_SCHEMA = "aine.control-plane.execution-request.v1"
PLAN_STATUSES = ("draft", "submitted", "approved", "rejected", "closed")
PLAN_RISKS = ("low", "medium", "high", "critical")
EXECUTION_STATUSES = ("requested", "running", "completed", "failed", "unknown", "cancelled")
EXECUTION_MODES = ("dry_run",)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _list_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _plan_record_id(plan_id: str, revision: int) -> str:
    return f"{plan_id}:r{revision}"


def _execution_record_id(execution_id: str, revision: int) -> str:
    return f"{execution_id}:r{revision}"


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
        "adapter_id": "local.remediation-workflow",
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


def validate_remediation_plan(record: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if record.get("schema") != REMEDIATION_PLAN_SCHEMA:
        errors.append("unsupported remediation plan schema")
    if not isinstance(record.get("plan_id"), str) or not record.get("plan_id"):
        errors.append("plan_id is required")
    if not isinstance(record.get("revision"), int) or record.get("revision", 0) < 1:
        errors.append("revision must be a positive integer")
    if record.get("status") not in PLAN_STATUSES:
        errors.append("status is unsupported")
    if record.get("risk") not in PLAN_RISKS:
        errors.append("risk is unsupported")
    for field in ("title", "rationale", "requested_by", "owner", "created_at"):
        if not isinstance(record.get(field), str) or not record.get(field, "").strip():
            errors.append(f"{field} is required")
    if not isinstance(record.get("scope"), Mapping):
        errors.append("scope must be an object")
    if not isinstance(record.get("finding"), Mapping):
        errors.append("finding must be an object")
    if not isinstance(record.get("strategy"), Mapping):
        errors.append("strategy must be an object")
    if not isinstance(record.get("validation"), Mapping):
        errors.append("validation must be an object")
    if not isinstance(record.get("acceptance_criteria"), list):
        errors.append("acceptance_criteria must be an array")
    if not isinstance(record.get("evidence_ids"), list):
        errors.append("evidence_ids must be an array")
    if not isinstance(record.get("approval_required"), bool):
        errors.append("approval_required must be boolean")
    if record.get("approval_required") is False and record.get("risk") != "low":
        errors.append("approval is required for medium, high, and critical risk plans")
    if record.get("read_only") is not True:
        errors.append("remediation plan records must remain read_only")
    finding = record.get("finding")
    if isinstance(finding, Mapping):
        if not str(finding.get("summary", "")).strip():
            errors.append("finding.summary is required")
    strategy = record.get("strategy")
    if isinstance(strategy, Mapping):
        if not str(strategy.get("description", "")).strip():
            errors.append("strategy.description is required")
    validation = record.get("validation")
    if isinstance(validation, Mapping) and not isinstance(validation.get("required_checks"), list):
        errors.append("validation.required_checks must be an array")
    for path in find_local_paths(record, "remediation_plan"):
        errors.append(f"runtime-local path is not allowed: {path}")
    return errors


def validate_execution_request(record: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if record.get("schema") != EXECUTION_REQUEST_SCHEMA:
        errors.append("unsupported execution request schema")
    for field in ("execution_id", "plan_id", "requested_by", "runner_kind", "created_at"):
        if not isinstance(record.get(field), str) or not record.get(field, "").strip():
            errors.append(f"{field} is required")
    if not isinstance(record.get("revision"), int) or record.get("revision", 0) < 1:
        errors.append("revision must be a positive integer")
    if record.get("status") not in ("requested", *EXECUTION_STATUSES):
        errors.append("status is unsupported")
    if record.get("mode") not in EXECUTION_MODES:
        errors.append("execution mode is unsupported")
    if not isinstance(record.get("mutation_scope"), Mapping):
        errors.append("mutation_scope must be an object")
    else:
        for field in ("source_repositories", "git", "deployment"):
            if record["mutation_scope"].get(field) is not False:
                errors.append(f"mutation_scope.{field} must be false")
    if not isinstance(record.get("validation"), Mapping):
        errors.append("validation must be an object")
    if not isinstance(record.get("evidence_ids"), list):
        errors.append("evidence_ids must be an array")
    if record.get("read_only") is not True:
        errors.append("execution request records must remain read_only")
    for path in find_local_paths(record, "execution_request"):
        errors.append(f"runtime-local path is not allowed: {path}")
    return errors


class RemediationWorkflow:
    """Append-only remediation plans and dry-run execution requests.

    This workflow records authority and evidence boundaries only. It never
    invokes an agent, executes a command, edits a repository, changes Git, or
    deploys a service. A separately authorized Local Runner may report a
    result through the execution request boundary.
    """

    def __init__(self, store: LocalRecordStore, approvals: ApprovalWorkflow | None = None, clock: Callable[[], str] = _now) -> None:
        self.store = store
        self.approvals = approvals or ApprovalWorkflow(store)
        self._clock = clock

    def create_plan(self, request: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]:
        plan_id = str(request.get("plan_id") or f"remediation.plan.{uuid4().hex}")
        record = {
            "schema": REMEDIATION_PLAN_SCHEMA,
            "plan_id": plan_id,
            "revision": 1,
            "status": "draft",
            "title": str(request.get("title", "")),
            "rationale": str(request.get("rationale", "")),
            "finding": _mapping(request.get("finding")),
            "scope": _mapping(request.get("scope")),
            "strategy": _mapping(request.get("strategy")),
            "validation": _mapping(request.get("validation")),
            "acceptance_criteria": _list_strings(request.get("acceptance_criteria", [])),
            "evidence_ids": _list_strings(request.get("evidence_ids", [])),
            **attribute_actor(request, context, "requested_by"),
            "owner": str(request.get("owner") or context.actor.get("id", "unknown")),
            "risk": str(request.get("risk", "medium")),
            "approval_required": bool(request.get("approval_required", True)),
            "created_at": str(request.get("created_at") or self._clock()),
            "read_only": True,
        }
        errors = validate_remediation_plan(record)
        if errors:
            return _outcome(context, "create_plan", "failure", error_code="invalid_remediation_plan", reasons=errors)
        result = self.store.put(record, context, record_type="remediation_plan", record_id=_plan_record_id(plan_id, 1))
        if result.get("status") == "success" and not result.get("result", {}).get("duplicate"):
            self.store.append_event("remediation.plan.created", plan_id, record, context)
        if result.get("status") != "success":
            return result
        response = dict(result)
        response["result"] = dict(result.get("result", {}))
        response["result"]["plan"] = record
        return response

    def list_plans(self) -> list[Mapping[str, Any]]:
        latest = self._latest_by("remediation_plan", "plan_id")
        return [self._with_plan_status(latest[key]) for key in sorted(latest)]

    def get_plan(self, plan_id: str) -> Mapping[str, Any] | None:
        latest = self._latest_by("remediation_plan", "plan_id").get(plan_id)
        return self._with_plan_status(latest) if latest else None

    def submit_plan(self, plan_id: str, context: AdapterContext) -> Mapping[str, Any]:
        current = self.get_plan(plan_id)
        if current is None:
            return _outcome(context, "submit_plan", "unknown", error_code="remediation_plan_not_found", reasons=[plan_id])
        if current.get("status") != "draft":
            return _outcome(context, "submit_plan", "failure", error_code="invalid_remediation_transition", reasons=[f"plan is already {current.get('status')}"])
        revision = int(current.get("revision", 0)) + 1
        submitted = dict(current)
        submitted.update({
            "revision": revision,
            "status": "submitted",
            "submitted_at": self._clock(),
            "previous_revision": int(current.get("revision", 0)),
        })
        if current.get("approval_required") is True:
            submitted["approval_id"] = "approval.remediation." + hashlib.sha256(f"{plan_id}:r{revision}".encode("utf-8")).hexdigest()[:20]
        errors = validate_remediation_plan(submitted)
        if errors:
            return _outcome(context, "submit_plan", "failure", error_code="invalid_remediation_plan", reasons=errors)
        result = self.store.put(submitted, context, record_type="remediation_plan", record_id=_plan_record_id(plan_id, revision))
        if result.get("status") != "success":
            return result
        self.store.append_event("remediation.plan.submitted", plan_id, submitted, context)
        approval = None
        approval_id = submitted.get("approval_id")
        if approval_id:
            self.approvals.create(
                {
                    "approval_id": approval_id,
                    "subject": {"plan_id": plan_id, "schema": REMEDIATION_PLAN_SCHEMA},
                    "scope": submitted["scope"],
                    "requested_by": submitted["requested_by"],
                    "required_approvals": 1,
                    "required_roles": ["approver"],
                    "evidence_ids": submitted["evidence_ids"],
                },
                context,
            )
            approval = self.approvals.get(approval_id)
        response = dict(result)
        response["result"] = dict(result.get("result", {}))
        response["result"]["plan"] = self.get_plan(plan_id) or submitted
        if approval is not None:
            response["result"]["approval"] = approval
        return response

    def request_dry_run(self, plan_id: str, context: AdapterContext) -> Mapping[str, Any]:
        plan = self.get_plan(plan_id)
        if plan is None:
            return _outcome(context, "request_dry_run", "unknown", error_code="remediation_plan_not_found", reasons=[plan_id])
        if plan.get("status") != "approved":
            return _outcome(context, "request_dry_run", "failure", error_code="remediation_approval_required", reasons=[f"plan status is {plan.get('status')}"])
        execution_id = "execution.remediation." + hashlib.sha256(f"{plan_id}:{plan.get('revision')}:dry_run".encode("utf-8")).hexdigest()[:24]
        record = {
            "schema": EXECUTION_REQUEST_SCHEMA,
            "execution_id": execution_id,
            "plan_id": plan_id,
            "revision": 1,
            "status": "requested",
            "mode": "dry_run",
            "runner_kind": "local_runner",
            "mutation_scope": {"source_repositories": False, "git": False, "deployment": False},
            "validation": dict(plan.get("validation", {})),
            "evidence_ids": list(plan.get("evidence_ids", [])),
            "requested_by": str(context.actor.get("id", "unknown")),
            "created_at": self._clock(),
            "read_only": True,
        }
        errors = validate_execution_request(record)
        if errors:
            return _outcome(context, "request_dry_run", "failure", error_code="invalid_execution_request", reasons=errors)
        result = self.store.put(record, context, record_type="execution_request", record_id=_execution_record_id(execution_id, 1))
        if result.get("status") == "success" and not result.get("result", {}).get("duplicate"):
            self.store.append_event("remediation.execution.requested", execution_id, record, context)
        if result.get("status") != "success":
            return result
        response = dict(result)
        response["result"] = dict(result.get("result", {}))
        response["result"]["execution"] = record
        return response

    def list_executions(self) -> list[Mapping[str, Any]]:
        latest = self._latest_by("execution_request", "execution_id")
        return [latest[key] for key in sorted(latest)]

    def get_execution(self, execution_id: str) -> Mapping[str, Any] | None:
        return self._latest_by("execution_request", "execution_id").get(execution_id)

    def report_execution(self, execution_id: str, request: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]:
        current = self.get_execution(execution_id)
        if current is None:
            return _outcome(context, "report_execution", "unknown", error_code="execution_request_not_found", reasons=[execution_id])
        if current.get("status") in ("completed", "failed", "cancelled"):
            return _outcome(context, "report_execution", "failure", error_code="execution_request_closed", reasons=[f"execution is already {current.get('status')}"])
        status = str(request.get("status", "unknown"))
        if status not in EXECUTION_STATUSES or status == "requested":
            return _outcome(context, "report_execution", "failure", error_code="invalid_execution_status", reasons=[status])
        record = dict(current)
        revision = int(current.get("revision", 0)) + 1
        record.update({
            "revision": revision,
            "status": status,
            "previous_revision": int(current.get("revision", 0)),
            "reported_at": self._clock(),
            "reported_by": str(context.actor.get("id", "unknown")),
            "result": _mapping(request.get("result")),
            "evidence_ids": _list_strings(request.get("evidence_ids", current.get("evidence_ids", []))),
        })
        errors = validate_execution_request(record)
        if errors:
            return _outcome(context, "report_execution", "failure", error_code="invalid_execution_request", reasons=errors)
        result = self.store.put(record, context, record_type="execution_request", record_id=_execution_record_id(execution_id, revision))
        if result.get("status") != "success":
            return result
        self.store.append_event(f"remediation.execution.{status}", execution_id, record, context)
        response = dict(result)
        response["result"] = dict(result.get("result", {}))
        response["result"]["execution"] = record
        return response

    def _latest_by(self, record_type: str, identity: str) -> dict[str, Mapping[str, Any]]:
        latest: dict[str, Mapping[str, Any]] = {}
        for record in self.store.list_records(record_type):
            key = record.get(identity)
            if not key:
                continue
            current = latest.get(str(key))
            if current is None or int(record.get("revision", 0)) > int(current.get("revision", 0)):
                latest[str(key)] = record
        return latest

    def _with_plan_status(self, record: Mapping[str, Any]) -> Mapping[str, Any]:
        result = dict(record)
        if result.get("status") == "submitted":
            approval_id = result.get("approval_id")
            if approval_id:
                approval = self.approvals.get(str(approval_id))
                if approval and approval.get("status") in ("approved", "rejected"):
                    result["status"] = approval["status"]
            elif result.get("approval_required") is False:
                result["status"] = "approved"
        return result
