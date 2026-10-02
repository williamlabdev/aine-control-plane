from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlsplit
from uuid import uuid4

from .contracts import AdapterContext, attribute_actor
from .remediation import RemediationWorkflow
from .store import LocalRecordStore
from .validation import find_local_paths


RUNNER_SESSION_SCHEMA = "aine.control-plane.runner-session.v1"
PATCH_ARTIFACT_SCHEMA = "aine.control-plane.patch-artifact.v1"
VALIDATION_REPORT_SCHEMA = "aine.control-plane.validation-report.v1"

RUNNER_SESSION_STATUSES = (
    "requested",
    "running",
    "completed",
    "failed",
    "unknown",
    "conflict",
    "cancelled",
    "closed",
)
TERMINAL_RUNNER_SESSION_STATUSES = ("completed", "failed", "cancelled", "closed")
RUNNER_OPERATION_PROFILES = ("dry_run_patch", "validation_only")
PATCH_ARTIFACT_STATUSES = ("proposed",)
PATCH_ARTIFACT_FORMATS = ("unified_diff", "git_patch", "file_manifest", "agent_patch")
VALIDATION_STATUSES = ("pass", "fail", "unknown", "conflict")

_RUNNER_SESSION_FIELDS = {
    "schema", "session_id", "revision", "status", "execution_id", "plan_id",
    "runner_kind", "operation_profile", "project_ids", "patch_artifact_ids",
    "validation_report_ids", "evidence_ids", "workspace_ref", "requested_by",
    "created_at", "reported_at", "reported_by", "updated_at", "previous_revision",
    "result", "mutation_scope", "read_only",
    "correlation_id", "authenticated_actor", "claimed_actor", "actor_source",
}
_PATCH_ARTIFACT_FIELDS = {
    "schema", "patch_id", "revision", "status", "session_id", "execution_id",
    "plan_id", "format", "content_digest", "artifact_ref", "base_revisions",
    "files", "file_count", "change_summary", "evidence_ids", "reported_by",
    "created_at", "mutation_scope", "read_only",
    "correlation_id", "authenticated_actor", "claimed_actor", "actor_source",
}
_VALIDATION_REPORT_FIELDS = {
    "schema", "report_id", "revision", "status", "session_id", "execution_id",
    "plan_id", "summary", "checks", "missing_check_ids", "evidence_ids",
    "runner_kind", "reported_by", "created_at", "mutation_scope", "read_only",
    "correlation_id", "authenticated_actor", "claimed_actor", "actor_source",
}
_PATCH_FILE_FIELDS = {"path", "old_path", "change"}
_VALIDATION_CHECK_FIELDS = {"check_id", "status", "summary", "evidence_ids"}

_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_CORRELATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def validate_correlation_id(value):
    """Validate the portable identifier shared by producer and runner records."""

    if not isinstance(value, str) or not _CORRELATION_ID_PATTERN.match(value):
        return ["correlation_id must be a portable identifier"]
    return []

_LOCAL_REFERENCE_PREFIXES = ("/", "~/", "file://")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _list_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _strict_string_list(value: Any, field: str) -> tuple[list[str], list[str]]:
    if not isinstance(value, list):
        return [], [f"{field} must be an array of non-empty strings"]
    values: list[str] = []
    errors: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{field}[{index}] must be a non-empty string")
        else:
            values.append(item.strip())
    return values, errors


def _append_unique(existing: Iterable[str], incoming: Iterable[str]) -> list[str]:
    return list(dict.fromkeys([*existing, *incoming]))


def _unknown_field_errors(record: Mapping[str, Any], allowed: set[str], record_name: str) -> list[str]:
    return [f"{record_name} contains unsupported field: {field}" for field in sorted(set(record) - allowed)]


def _outcome(
    context: AdapterContext,
    operation: str,
    status: str,
    *,
    result: Mapping[str, Any] | None = None,
    error_code: str | None = None,
    reasons: Iterable[str] = (),
    conflict_ids: Iterable[str] = (),
) -> dict[str, Any]:
    outcome: dict[str, Any] = {
        "schema": "aine.control-plane.adapter-outcome.v1",
        "status": status,
        "adapter_id": "local.runner-protocol",
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
    conflict_list = [str(conflict_id) for conflict_id in conflict_ids if conflict_id]
    if conflict_list:
        outcome["conflict_ids"] = conflict_list
    return outcome


def _mutation_scope_errors(record: Mapping[str, Any], record_name: str) -> list[str]:
    errors: list[str] = []
    scope = record.get("mutation_scope")
    if not isinstance(scope, Mapping):
        return ["mutation_scope must be an object"]
    for field in ("source_repositories", "git", "deployment"):
        if scope.get(field) is not False:
            errors.append(f"mutation_scope.{field} must be false")
    if record.get("read_only") is not True:
        errors.append(f"{record_name} records must remain read_only")
    return errors


def _portable_reference_errors(value: Any, field: str) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return [f"{field} must be a non-empty URI reference"]
    if any(character.isspace() for character in value):
        return [f"{field} must not contain whitespace"]
    lowered = value.lower()
    if lowered.startswith(_LOCAL_REFERENCE_PREFIXES):
        return [f"runtime-local reference is not allowed: {field}"]
    try:
        parsed = urlsplit(value)
    except ValueError:
        return [f"{field} must be a valid URI reference"]
    if not parsed.scheme:
        return [f"{field} must include a URI scheme"]
    if parsed.scheme.lower() == "file":
        return [f"{field} must not use the file:// scheme"]
    if parsed.username is not None or parsed.password is not None:
        return [f"{field} must not contain URI userinfo"]
    if "?" in value or "#" in value:
        return [f"{field} must not contain a query or fragment"]
    return []


def _relative_path_errors(value: Any, field: str) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return [f"{field} must be a non-empty relative path"]
    normalized = value.replace("\\", "/")
    if normalized.startswith(("/", "~/")) or bool(re.match(r"^[A-Za-z]:/", normalized)):
        return [f"runtime-local path is not allowed: {field}"]
    if normalized.lower().startswith("file://"):
        return [f"runtime-local path is not allowed: {field}"]
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", normalized):
        return [f"file manifest paths must be relative: {field}"]
    if ".." in normalized.split("/"):
        return [f"file manifest paths must stay within the project scope: {field}"]
    return []


def _sha256_errors(value: Any, field: str) -> list[str]:
    if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
        return [f"{field} must be a sha256 digest"]
    return []


def validate_runner_session(record: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    errors.extend(_unknown_field_errors(record, _RUNNER_SESSION_FIELDS, "runner session"))
    if record.get("schema") != RUNNER_SESSION_SCHEMA:
        errors.append("unsupported runner session schema")
    for field in (
        "session_id",
        "execution_id",
        "plan_id",
        "runner_kind",
        "operation_profile",
        "requested_by",
        "created_at",
    ):
        if not isinstance(record.get(field), str) or not record.get(field, "").strip():
            errors.append(f"{field} is required")
    if not isinstance(record.get("revision"), int) or record.get("revision", 0) < 1:
        errors.append("revision must be a positive integer")
    if record.get("status") not in RUNNER_SESSION_STATUSES:
        errors.append("runner session status is unsupported")
    if record.get("runner_kind") != "local_runner":
        errors.append("runner_kind must be local_runner")
    if record.get("operation_profile") not in RUNNER_OPERATION_PROFILES:
        errors.append("runner operation_profile is unsupported")
    for field in ("project_ids", "patch_artifact_ids", "validation_report_ids", "evidence_ids"):
        if not isinstance(record.get(field), list) or not all(isinstance(item, str) and item.strip() for item in record.get(field, [])):
            errors.append(f"{field} must be an array of non-empty strings")
    if isinstance(record.get("project_ids"), list) and not record.get("project_ids"):
        errors.append("project_ids must contain at least one explicit project scope")
    errors.extend(_mutation_scope_errors(record, "runner session"))
    if "correlation_id" in record:
        errors.extend(validate_correlation_id(record.get("correlation_id")))
    if "workspace_ref" in record:
        errors.extend(_portable_reference_errors(record.get("workspace_ref"), "workspace_ref"))
    for path in find_local_paths(record, "runner_session"):
        errors.append(f"runtime-local path is not allowed: {path}")
    return errors


def validate_patch_artifact(record: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    errors.extend(_unknown_field_errors(record, _PATCH_ARTIFACT_FIELDS, "patch artifact"))
    if record.get("schema") != PATCH_ARTIFACT_SCHEMA:
        errors.append("unsupported patch artifact schema")
    for field in (
        "patch_id",
        "session_id",
        "execution_id",
        "plan_id",
        "format",
        "change_summary",
        "reported_by",
        "created_at",
    ):
        if not isinstance(record.get(field), str) or not record.get(field, "").strip():
            errors.append(f"{field} is required")
    if not isinstance(record.get("revision"), int) or record.get("revision", 0) < 1:
        errors.append("revision must be a positive integer")
    if record.get("status") not in PATCH_ARTIFACT_STATUSES:
        errors.append("patch artifact status is unsupported; an artifact cannot be applied by the Control Plane")
    if record.get("format") not in PATCH_ARTIFACT_FORMATS:
        errors.append("patch artifact format is unsupported")
    for field in ("diff", "content", "patch"):
        if field in record:
            errors.append(f"{field} is not accepted; submit metadata and an external artifact_ref only")
    errors.extend(_sha256_errors(record.get("content_digest"), "content_digest"))
    files = record.get("files")
    if not isinstance(files, list) or not files:
        errors.append("files must be a non-empty array")
    else:
        for index, file_record in enumerate(files):
            if not isinstance(file_record, Mapping):
                errors.append(f"files[{index}] must be an object")
                continue
            errors.extend(_unknown_field_errors(file_record, _PATCH_FILE_FIELDS, f"files[{index}]"))
            errors.extend(_relative_path_errors(file_record.get("path"), f"files[{index}].path"))
            if "old_path" in file_record:
                errors.extend(_relative_path_errors(file_record.get("old_path"), f"files[{index}].old_path"))
            if file_record.get("change") not in ("added", "modified", "deleted", "renamed"):
                errors.append(f"files[{index}].change is unsupported")
    file_count_matches = isinstance(files, list) and isinstance(record.get("file_count"), int) and record.get("file_count") == len(files)
    if not file_count_matches:
        errors.append("file_count must match files length")
    if not isinstance(record.get("evidence_ids"), list) or not all(isinstance(item, str) for item in record.get("evidence_ids", [])):
        errors.append("evidence_ids must be an array of strings")
    if "artifact_ref" in record:
        errors.extend(_portable_reference_errors(record.get("artifact_ref"), "artifact_ref"))
    errors.extend(_mutation_scope_errors(record, "patch artifact"))
    if "correlation_id" in record:
        errors.extend(validate_correlation_id(record.get("correlation_id")))
    for path in find_local_paths(record, "patch_artifact"):
        errors.append(f"runtime-local path is not allowed: {path}")
    return errors


def _validate_check(check: Any, index: int) -> list[str]:
    if not isinstance(check, Mapping):
        return [f"checks[{index}] must be an object"]
    errors: list[str] = []
    errors.extend(_unknown_field_errors(check, _VALIDATION_CHECK_FIELDS, f"checks[{index}]"))
    for field in ("check_id", "summary"):
        if not isinstance(check.get(field), str) or not check.get(field, "").strip():
            errors.append(f"checks[{index}].{field} is required")
    if check.get("status") not in VALIDATION_STATUSES:
        errors.append(f"checks[{index}].status is unsupported")
    if "evidence_ids" in check and (
        not isinstance(check.get("evidence_ids"), list)
        or not all(isinstance(item, str) for item in check.get("evidence_ids", []))
    ):
        errors.append(f"checks[{index}].evidence_ids must be an array of strings")
    return errors


def validate_validation_report(record: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    errors.extend(_unknown_field_errors(record, _VALIDATION_REPORT_FIELDS, "validation report"))
    if record.get("schema") != VALIDATION_REPORT_SCHEMA:
        errors.append("unsupported validation report schema")
    for field in ("report_id", "session_id", "execution_id", "plan_id", "summary", "runner_kind", "reported_by", "created_at"):
        if not isinstance(record.get(field), str) or not record.get(field, "").strip():
            errors.append(f"{field} is required")
    if not isinstance(record.get("revision"), int) or record.get("revision", 0) < 1:
        errors.append("revision must be a positive integer")
    if record.get("status") not in VALIDATION_STATUSES:
        errors.append("validation report status is unsupported")
    if record.get("runner_kind") != "local_runner":
        errors.append("runner_kind must be local_runner")
    checks = record.get("checks")
    if not isinstance(checks, list):
        errors.append("checks must be an array")
    else:
        seen: set[str] = set()
        for index, check in enumerate(checks):
            errors.extend(_validate_check(check, index))
            if isinstance(check, Mapping) and isinstance(check.get("check_id"), str):
                if check["check_id"] in seen:
                    errors.append(f"checks[{index}].check_id must be unique")
                seen.add(check["check_id"])
    if not isinstance(record.get("evidence_ids"), list) or not all(isinstance(item, str) and item.strip() for item in record.get("evidence_ids", [])):
        errors.append("evidence_ids must be an array of non-empty strings")
    if "missing_check_ids" in record and (
        not isinstance(record.get("missing_check_ids"), list)
        or not all(isinstance(item, str) and item.strip() for item in record.get("missing_check_ids", []))
    ):
        errors.append("missing_check_ids must be an array of non-empty strings")
    errors.extend(_mutation_scope_errors(record, "validation report"))
    if "correlation_id" in record:
        errors.extend(validate_correlation_id(record.get("correlation_id")))
    for path in find_local_paths(record, "validation_report"):
        errors.append(f"runtime-local path is not allowed: {path}")
    return errors


class RunnerWorkflow:
    """Record an external Local Runner protocol without executing it.

    The workflow creates append-only session, patch metadata, and validation
    report records. It never starts a runner, invokes an agent, reads a local
    workspace, applies a patch, changes Git, or deploys a service.
    """

    def __init__(
        self,
        store: LocalRecordStore,
        remediation: RemediationWorkflow,
        clock: Callable[[], str] = _now,
    ) -> None:
        self.store = store
        self.remediation = remediation
        self._clock = clock

    def create_session(self, execution_id: str, request: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]:
        execution = self.remediation.get_execution(execution_id)
        if execution is None:
            return _outcome(context, "create_session", "unknown", error_code="execution_request_not_found", reasons=[execution_id])
        if execution.get("mode") != "dry_run" or execution.get("runner_kind") != "local_runner":
            return _outcome(context, "create_session", "failure", error_code="unsupported_runner_execution", reasons=[execution_id])
        if execution.get("status") not in ("requested", "running"):
            return _outcome(
                context,
                "create_session",
                "failure",
                error_code="execution_request_not_open",
                reasons=[f"execution is already {execution.get('status')}"],
            )
        plan = self.remediation.get_plan(str(execution.get("plan_id", ""))) or {}
        if "project_ids" in request:
            project_ids, project_id_errors = _strict_string_list(request.get("project_ids"), "project_ids")
        else:
            project_ids = _list_strings(_mapping(plan.get("scope")).get("project_ids"))
            project_id_errors = []
        evidence_ids, evidence_id_errors = _strict_string_list(request.get("evidence_ids", []), "evidence_ids")
        operation_profile = str(request.get("operation_profile", "dry_run_patch"))
        session_id = str(request.get("session_id") or "runner.session." + hashlib.sha256(execution_id.encode("utf-8")).hexdigest()[:24])
        existing = self.get_session(session_id)
        if existing is not None:
            if existing.get("execution_id") != execution_id:
                return _outcome(
                    context,
                    "create_session",
                    "conflict",
                    error_code="runner_session_id_conflict",
                    reasons=[session_id],
                    conflict_ids=[session_id],
                )
            return _outcome(context, "create_session", "success", result={"session": existing, "duplicate": True})
        record = {
            "schema": RUNNER_SESSION_SCHEMA,
            "session_id": session_id,
            "revision": 1,
            "status": "requested",
            "execution_id": execution_id,
            "plan_id": str(execution.get("plan_id", "")),
            "runner_kind": "local_runner",
            "operation_profile": operation_profile,
            "project_ids": project_ids,
            "patch_artifact_ids": [],
            "validation_report_ids": [],
            "evidence_ids": evidence_ids,
            **attribute_actor(request, context, "requested_by"),
            "created_at": str(request.get("created_at") or self._clock()),
            "mutation_scope": {"source_repositories": False, "git": False, "deployment": False},
            "read_only": True,
        }
        if request.get("correlation_id") is not None:
            record["correlation_id"] = request.get("correlation_id")
        if request.get("workspace_ref") is not None:
            record["workspace_ref"] = request.get("workspace_ref")
        errors = [*project_id_errors, *evidence_id_errors, *validate_runner_session(record)]
        if errors:
            return _outcome(context, "create_session", "failure", error_code="invalid_runner_session", reasons=errors)
        result = self.store.put(record, context, record_type="runner_session", record_id=_session_record_id(session_id, 1))
        if result.get("status") == "success" and not result.get("result", {}).get("duplicate"):
            self.store.append_event("runner.session.requested", session_id, record, context)
        if result.get("status") != "success":
            return result
        response = dict(result)
        response["result"] = dict(result.get("result", {}))
        response["result"]["session"] = record
        return response

    def list_sessions(self) -> list[Mapping[str, Any]]:
        latest = self._latest_by("runner_session", "session_id")
        return [latest[key] for key in sorted(latest)]

    def get_session(self, session_id: str) -> Mapping[str, Any] | None:
        return self._latest_by("runner_session", "session_id").get(session_id)

    def report_session(self, session_id: str, request: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]:
        current = self.get_session(session_id)
        if current is None:
            return _outcome(context, "report_session", "unknown", error_code="runner_session_not_found", reasons=[session_id])
        if current.get("status") in TERMINAL_RUNNER_SESSION_STATUSES:
            return _outcome(context, "report_session", "failure", error_code="runner_session_closed", reasons=[f"session is already {current.get('status')}"])
        status = str(request.get("status", "unknown"))
        if status not in RUNNER_SESSION_STATUSES or status == "requested":
            return _outcome(context, "report_session", "failure", error_code="invalid_runner_session_status", reasons=[status])
        revision = int(current.get("revision", 0)) + 1
        record = dict(current)
        patch_artifact_ids, patch_id_errors = _strict_string_list(
            request.get("patch_artifact_ids", current.get("patch_artifact_ids", [])),
            "patch_artifact_ids",
        )
        validation_report_ids, validation_id_errors = _strict_string_list(
            request.get("validation_report_ids", current.get("validation_report_ids", [])),
            "validation_report_ids",
        )
        evidence_ids, evidence_id_errors = _strict_string_list(
            request.get("evidence_ids", current.get("evidence_ids", [])),
            "evidence_ids",
        )
        patch_artifact_ids = _append_unique(current.get("patch_artifact_ids", []), patch_artifact_ids)
        validation_report_ids = _append_unique(current.get("validation_report_ids", []), validation_report_ids)
        evidence_ids = _append_unique(current.get("evidence_ids", []), evidence_ids)
        relationship_errors = [*patch_id_errors, *validation_id_errors, *evidence_id_errors]
        relationship_errors.extend(self._relationship_errors(session_id, "patch_artifact_ids", patch_artifact_ids))
        relationship_errors.extend(self._relationship_errors(session_id, "validation_report_ids", validation_report_ids))
        if relationship_errors:
            return _outcome(context, "report_session", "failure", error_code="invalid_runner_relationships", reasons=relationship_errors)
        record.update(
            {
                "revision": revision,
                "status": status,
                "previous_revision": int(current.get("revision", 0)),
                "reported_at": self._clock(),
                "reported_by": str(context.actor.get("id", "unknown")),
                "patch_artifact_ids": patch_artifact_ids,
                "validation_report_ids": validation_report_ids,
                "evidence_ids": evidence_ids,
            }
        )
        if "result" in request:
            if not isinstance(request.get("result"), Mapping):
                return _outcome(context, "report_session", "failure", error_code="invalid_runner_session", reasons=["result must be an object"])
            record["result"] = dict(request["result"])
        errors = validate_runner_session(record)
        if errors:
            return _outcome(context, "report_session", "failure", error_code="invalid_runner_session", reasons=errors)
        result = self.store.put(record, context, record_type="runner_session", record_id=_session_record_id(session_id, revision))
        if result.get("status") != "success":
            return result
        self.store.append_event(f"runner.session.{status}", session_id, record, context)
        response = dict(result)
        response["result"] = dict(result.get("result", {}))
        response["result"]["session"] = record
        return response

    def create_patch_artifact(self, session_id: str, request: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]:
        session = self.get_session(session_id)
        if session is None:
            return _outcome(context, "create_patch_artifact", "unknown", error_code="runner_session_not_found", reasons=[session_id])
        if session.get("status") in TERMINAL_RUNNER_SESSION_STATUSES:
            return _outcome(context, "create_patch_artifact", "failure", error_code="runner_session_closed", reasons=[f"session is already {session.get('status')}"])
        if request.get("status") not in (None, "proposed"):
            return _outcome(context, "create_patch_artifact", "failure", error_code="patch_application_not_allowed", reasons=[str(request.get("status"))])
        if request.get("correlation_id") is not None and request.get("correlation_id") != session.get("correlation_id"):
            return _outcome(context, "create_patch_artifact", "conflict", error_code="runner_correlation_mismatch", reasons=["patch correlation_id must match its runner session"], conflict_ids=[session_id])
        if "diff" in request or "content" in request or "patch" in request:
            return _outcome(context, "create_patch_artifact", "failure", error_code="raw_patch_payload_not_accepted", reasons=["submit metadata and an external artifact_ref only"])
        patch_id = str(request.get("patch_id") or "patch.artifact." + uuid4().hex)
        evidence_ids, evidence_id_errors = _strict_string_list(request.get("evidence_ids", []), "evidence_ids")
        record = {
            "schema": PATCH_ARTIFACT_SCHEMA,
            "patch_id": patch_id,
            "revision": 1,
            "status": "proposed",
            "session_id": session_id,
            "execution_id": str(session.get("execution_id", "")),
            "plan_id": str(session.get("plan_id", "")),
            "format": str(request.get("format", "file_manifest")),
            "content_digest": str(request.get("content_digest", "")),
            "files": [dict(item) if isinstance(item, Mapping) else item for item in request.get("files", [])] if isinstance(request.get("files", []), list) else request.get("files"),
            "file_count": request.get("file_count", len(request.get("files", [])) if isinstance(request.get("files"), list) else 0),
            "change_summary": str(request.get("change_summary", "")),
            "evidence_ids": evidence_ids,
            **attribute_actor(request, context, "reported_by"),
            "created_at": str(request.get("created_at") or self._clock()),
            "mutation_scope": {"source_repositories": False, "git": False, "deployment": False},
            "read_only": True,
        }
        if session.get("correlation_id") is not None:
            record["correlation_id"] = session.get("correlation_id")
        for field in ("artifact_ref", "base_revisions"):
            if field in request:
                record[field] = request[field]
        errors = [*evidence_id_errors, *validate_patch_artifact(record)]
        if errors:
            return _outcome(context, "create_patch_artifact", "failure", error_code="invalid_patch_artifact", reasons=errors)
        result = self.store.put(record, context, record_type="patch_artifact", record_id=_patch_record_id(patch_id, 1))
        if result.get("status") == "success" and not result.get("result", {}).get("duplicate"):
            self.store.append_event("runner.patch.created", patch_id, record, context)
            self._link_session(session, "patch_artifact_ids", patch_id, context)
        if result.get("status") != "success":
            return result
        response = dict(result)
        response["result"] = dict(result.get("result", {}))
        response["result"]["patch_artifact"] = record
        return response

    def list_patch_artifacts(self) -> list[Mapping[str, Any]]:
        latest = self._latest_by("patch_artifact", "patch_id")
        return [latest[key] for key in sorted(latest)]

    def get_patch_artifact(self, patch_id: str) -> Mapping[str, Any] | None:
        return self._latest_by("patch_artifact", "patch_id").get(patch_id)

    def create_validation_report(self, session_id: str, request: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]:
        session = self.get_session(session_id)
        if session is None:
            return _outcome(context, "create_validation_report", "unknown", error_code="runner_session_not_found", reasons=[session_id])
        if session.get("status") in TERMINAL_RUNNER_SESSION_STATUSES:
            return _outcome(context, "create_validation_report", "failure", error_code="runner_session_closed", reasons=[f"session is already {session.get('status')}"])
        if request.get("correlation_id") is not None and request.get("correlation_id") != session.get("correlation_id"):
            return _outcome(context, "create_validation_report", "conflict", error_code="runner_correlation_mismatch", reasons=["validation correlation_id must match its runner session"], conflict_ids=[session_id])
        report_id = str(request.get("report_id") or "validation.report." + uuid4().hex)
        checks = [dict(item) if isinstance(item, Mapping) else item for item in request.get("checks", [])] if isinstance(request.get("checks", []), list) else request.get("checks")
        evidence_ids, evidence_id_errors = _strict_string_list(request.get("evidence_ids", []), "evidence_ids")
        missing_check_ids, missing_check_id_errors = _strict_string_list(request.get("missing_check_ids", []), "missing_check_ids")
        record = {
            "schema": VALIDATION_REPORT_SCHEMA,
            "report_id": report_id,
            "revision": 1,
            "status": str(request.get("status", "unknown")),
            "session_id": session_id,
            "execution_id": str(session.get("execution_id", "")),
            "plan_id": str(session.get("plan_id", "")),
            "summary": str(request.get("summary", "")),
            "checks": checks,
            "evidence_ids": evidence_ids,
            "missing_check_ids": missing_check_ids,
            "runner_kind": "local_runner",
            **attribute_actor(request, context, "reported_by"),
            "created_at": str(request.get("created_at") or self._clock()),
            "mutation_scope": {"source_repositories": False, "git": False, "deployment": False},
            "read_only": True,
        }
        if session.get("correlation_id") is not None:
            record["correlation_id"] = session.get("correlation_id")
        errors = [*evidence_id_errors, *missing_check_id_errors, *validate_validation_report(record)]
        if errors:
            return _outcome(context, "create_validation_report", "failure", error_code="invalid_validation_report", reasons=errors)
        result = self.store.put(record, context, record_type="validation_report", record_id=_report_record_id(report_id, 1))
        if result.get("status") == "success" and not result.get("result", {}).get("duplicate"):
            self.store.append_event("runner.validation.reported", report_id, record, context)
            self._link_session(session, "validation_report_ids", report_id, context)
        if result.get("status") != "success":
            return result
        response = dict(result)
        response["result"] = dict(result.get("result", {}))
        response["result"]["validation_report"] = record
        return response

    def list_validation_reports(self) -> list[Mapping[str, Any]]:
        latest = self._latest_by("validation_report", "report_id")
        return [latest[key] for key in sorted(latest)]

    def get_validation_report(self, report_id: str) -> Mapping[str, Any] | None:
        return self._latest_by("validation_report", "report_id").get(report_id)

    def _link_session(self, current: Mapping[str, Any], field: str, value: str, context: AdapterContext) -> None:
        values = _list_strings(current.get(field, []))
        if value in values:
            return
        revision = int(current.get("revision", 0)) + 1
        record = dict(current)
        record.update(
            {
                "revision": revision,
                "previous_revision": int(current.get("revision", 0)),
                field: [*values, value],
                "updated_at": self._clock(),
            }
        )
        if validate_runner_session(record):
            return
        result = self.store.put(record, context, record_type="runner_session", record_id=_session_record_id(str(current["session_id"]), revision))
        if result.get("status") == "success" and not result.get("result", {}).get("duplicate"):
            self.store.append_event("runner.session.linked", str(current["session_id"]), record, context)

    def _relationship_errors(self, session_id: str, field: str, values: Iterable[str]) -> list[str]:
        errors: list[str] = []
        getter = self.get_patch_artifact if field == "patch_artifact_ids" else self.get_validation_report
        for value in values:
            target = getter(value)
            if target is None:
                errors.append(f"{field} references unknown record: {value}")
            elif target.get("session_id") != session_id:
                errors.append(f"{field} references a record owned by another session: {value}")
        return errors

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


def _session_record_id(session_id: str, revision: int) -> str:
    return f"{session_id}:r{revision}"


def _patch_record_id(patch_id: str, revision: int) -> str:
    return f"{patch_id}:r{revision}"


def _report_record_id(report_id: str, revision: int) -> str:
    return f"{report_id}:r{revision}"
