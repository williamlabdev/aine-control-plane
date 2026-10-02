from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping
from urllib.parse import parse_qs, unquote, urlparse
from uuid import uuid4

from .contracts import AdapterContext
from .service import ControlPlaneService


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    server: "ControlPlaneHTTPServer"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        include_retired = query.get("include_retired", ["false"])[0].strip().lower() in {"1", "true", "yes"}
        if path == "/healthz":
            self._respond(200, self.server.service.health())
            return
        if path == "/v1/contract":
            self._respond(200, self.server.service.contract())
            return
        if path == "/v1/adapters":
            self._respond(200, {"adapters": self.server.service.adapters(), "read_only": True})
            return
        if path == "/v1/projects":
            self._respond(
                200,
                {"projects": self.server.service.projects(include_retired=include_retired), "read_only": True},
            )
            return
        if path == "/v1/relationships":
            self._respond(
                200,
                {
                    "schema": "aine.control-plane.relationships-view.v1",
                    "relationships": self.server.service.relationships(
                        query.get("project_id", [None])[0],
                        query.get("relationship_type", [None])[0],
                        query.get("status", [None])[0],
                        include_retired=include_retired,
                    ),
                    "provenance": self.server.service.portfolio_provenance(),
                    "read_only": True,
                },
            )
            return
        if path == "/v1/source-of-truth":
            self._respond(
                200,
                {
                    "schema": "aine.control-plane.source-of-truth-view.v1",
                    "source_of_truth": self.server.service.source_of_truth(
                        query.get("domain", [None])[0],
                        query.get("project_id", [None])[0],
                    ),
                    "provenance": self.server.service.portfolio_provenance(),
                    "read_only": True,
                },
            )
            return
        if path == "/v1/change-requests":
            self._respond(200, {"change_requests": self.server.service.list_change_requests(), "read_only": True})
            return
        if path.startswith("/v1/change-requests/"):
            change_id = unquote(path[len("/v1/change-requests/") :].strip("/"))
            change_request = self.server.service.get_change_request(change_id)
            self._respond(
                200 if change_request else 404,
                change_request or {"error": "change_request_not_found", "change_id": change_id},
            )
            return
        if path == "/v1/remediation-plans":
            self._respond(200, {"plans": self.server.service.list_remediation_plans(), "read_only": True})
            return
        if path.startswith("/v1/remediation-plans/"):
            plan_id = unquote(path[len("/v1/remediation-plans/") :].strip("/"))
            plan = self.server.service.get_remediation_plan(plan_id)
            self._respond(200 if plan else 404, plan or {"error": "remediation_plan_not_found", "plan_id": plan_id})
            return
        if path == "/v1/execution-requests":
            self._respond(200, {"executions": self.server.service.list_remediation_executions(), "read_only": True})
            return
        if path.startswith("/v1/execution-requests/"):
            execution_id = unquote(path[len("/v1/execution-requests/") :].strip("/"))
            execution = self.server.service.get_remediation_execution(execution_id)
            self._respond(200 if execution else 404, execution or {"error": "execution_request_not_found", "execution_id": execution_id})
            return
        if path == "/v1/runner-sessions":
            self._respond(200, {"sessions": self.server.service.list_runner_sessions(), "read_only": True})
            return
        if path.startswith("/v1/runner-sessions/"):
            session_id = unquote(path[len("/v1/runner-sessions/") :].strip("/"))
            session = self.server.service.get_runner_session(session_id)
            self._respond(200 if session else 404, session or {"error": "runner_session_not_found", "session_id": session_id})
            return
        if path == "/v1/patch-artifacts":
            self._respond(200, {"patch_artifacts": self.server.service.list_patch_artifacts(), "read_only": True})
            return
        if path.startswith("/v1/patch-artifacts/"):
            patch_id = unquote(path[len("/v1/patch-artifacts/") :].strip("/"))
            artifact = self.server.service.get_patch_artifact(patch_id)
            self._respond(200 if artifact else 404, artifact or {"error": "patch_artifact_not_found", "patch_id": patch_id})
            return
        if path == "/v1/validation-reports":
            self._respond(200, {"validation_reports": self.server.service.list_validation_reports(), "read_only": True})
            return
        if path.startswith("/v1/validation-reports/"):
            report_id = unquote(path[len("/v1/validation-reports/") :].strip("/"))
            report = self.server.service.get_validation_report(report_id)
            self._respond(200 if report else 404, report or {"error": "validation_report_not_found", "report_id": report_id})
            return
        if path.startswith("/v1/projects/") and path.endswith("/impact"):
            project_id = path[len("/v1/projects/") : -len("/impact")].strip("/")
            self._respond(200, self.server.service.impact(project_id))
            return
        if path.startswith("/v1/projects/"):
            project_id = path[len("/v1/projects/") :].strip("/")
            project = self.server.service.get_project(project_id)
            self._respond(200 if project else 404, project or {"error": "project_not_found", "project_id": project_id})
            return
        if path == "/v1/evidence":
            self._respond(200, {"records": self.server.service.list_evidence(), "read_only": True})
            return
        if path == "/v1/audit/events":
            query = parse_qs(urlparse(self.path).query)
            aggregate_id = query.get("aggregate_id", [None])[0]
            self._respond(200, {"events": self.server.service.audit_events(aggregate_id), "read_only": True})
            return
        if path == "/v1/audit/actor-attribution":
            query = parse_qs(urlparse(self.path).query)
            day = query.get("day", [None])[0]
            self._respond(200, self.server.service.actor_attribution(day))
            return
        if path.startswith("/v1/evidence/"):
            record_id = path[len("/v1/evidence/") :].strip("/")
            record = self.server.service.get_evidence(record_id)
            self._respond(200 if record else 404, record or {"error": "evidence_not_found", "record_id": record_id})
            return
        if path.startswith("/v1/approvals/"):
            approval_id = path[len("/v1/approvals/") :].strip("/")
            approval = self.server.service.get_approval(approval_id)
            self._respond(200 if approval else 404, approval or {"error": "approval_not_found", "approval_id": approval_id})
            return
        self._respond(404, {"error": "not_found", "path": path})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in (
            "/v1/evidence",
            "/v1/snapshots",
            "/v1/policies/evaluate",
            "/v1/authorization/evaluate",
            "/v1/retention/evaluate",
            "/v1/approvals",
            "/v1/change-requests",
            "/v1/remediation-plans",
            "/v1/export",
        ):
            context = self._context(require_actor=True)
            if context is None:
                return
            body = self._body()
            if body is None:
                return
            if path == "/v1/evidence":
                self._respond(201, self.server.service.put_evidence(body, context))
                return
            if path == "/v1/snapshots":
                result = self.server.service.ingest_snapshot(body, context)
                self._respond(201 if result.get("status") == "success" else 422, result)
                return
            if path == "/v1/policies/evaluate":
                policy = body.get("policy", {})
                checks = body.get("checks", [])
                result = self.server.service.evaluate_policy(policy, checks, context, body.get("mode"))
                self._respond(409 if result.get("blocked") else 200, result)
                return
            if path == "/v1/authorization/evaluate":
                result = self.server.service.authorize(
                    body.get("subject", {}),
                    str(body.get("action", "")),
                    str(body.get("resource", "")),
                    context,
                )
                status = 200 if result.get("status") == "allow" else 403 if result.get("status") == "deny" else 409
                self._respond(status, result)
                return
            if path == "/v1/retention/evaluate":
                self._respond(200, self.server.service.retention(body))
                return
            if path == "/v1/approvals":
                result = self.server.service.create_approval(body, context)
                self._respond(201 if result.get("status") == "success" else 422, result)
                return
            if path == "/v1/change-requests":
                result = self.server.service.create_change_request(body, context)
                self._respond(201 if result.get("status") == "success" else 422, result)
                return
            if path == "/v1/remediation-plans":
                result = self.server.service.create_remediation_plan(body, context)
                self._respond(201 if result.get("status") == "success" else 422, result)
                return
            if path == "/v1/export":
                destination = body.get("destination")
                if not isinstance(destination, str) or not destination:
                    self._respond(422, {"error": "destination_required"})
                    return
                self._respond(200, self.server.service.export(destination))
                return

        if path.startswith("/v1/approvals/") and path.endswith("/decision"):
            context = self._context(require_actor=True)
            if context is None:
                return
            body = self._body()
            if body is None:
                return
            approval_id = path[len("/v1/approvals/") : -len("/decision")].strip("/")
            result = self.server.service.decide_approval(
                approval_id,
                str(body.get("decision", "")),
                str(body.get("reason", "")),
                context,
            )
            self._respond(200 if result.get("status") == "success" else 422, result)
            return

        if path.startswith("/v1/change-requests/") and path.endswith("/submit"):
            context = self._context(require_actor=True)
            if context is None:
                return
            change_id = unquote(path[len("/v1/change-requests/") : -len("/submit")].strip("/"))
            result = self.server.service.submit_change_request(change_id, context)
            status = 200 if result.get("status") == "success" else 404 if result.get("status") == "unknown" else 422
            self._respond(status, result)
            return

        if path.startswith("/v1/remediation-plans/") and path.endswith("/submit"):
            context = self._context(require_actor=True)
            if context is None:
                return
            plan_id = unquote(path[len("/v1/remediation-plans/") : -len("/submit")].strip("/"))
            result = self.server.service.submit_remediation_plan(plan_id, context)
            status = 200 if result.get("status") == "success" else 404 if result.get("status") == "unknown" else 422
            self._respond(status, result)
            return

        if path.startswith("/v1/remediation-plans/") and path.endswith("/execution"):
            context = self._context(require_actor=True)
            if context is None:
                return
            plan_id = unquote(path[len("/v1/remediation-plans/") : -len("/execution")].strip("/"))
            result = self.server.service.request_remediation_dry_run(plan_id, context)
            status = 201 if result.get("status") == "success" else 404 if result.get("status") == "unknown" else 409 if result.get("error_code") == "remediation_approval_required" else 422
            self._respond(status, result)
            return

        if path.startswith("/v1/execution-requests/") and path.endswith("/report"):
            context = self._context(require_actor=True)
            if context is None:
                return
            body = self._body()
            if body is None:
                return
            execution_id = unquote(path[len("/v1/execution-requests/") : -len("/report")].strip("/"))
            result = self.server.service.report_remediation_execution(execution_id, body, context)
            status = 200 if result.get("status") == "success" else 404 if result.get("status") == "unknown" else 422
            self._respond(status, result)
            return

        if path.startswith("/v1/execution-requests/") and path.endswith("/runner-session"):
            context = self._context(require_actor=True)
            if context is None:
                return
            body = self._body()
            if body is None:
                return
            execution_id = unquote(path[len("/v1/execution-requests/") : -len("/runner-session")].strip("/"))
            result = self.server.service.create_runner_session(execution_id, body, context)
            status = 201 if result.get("status") == "success" else 404 if result.get("status") == "unknown" else 409 if result.get("error_code") == "execution_request_not_open" else 422
            self._respond(status, result)
            return

        if path.startswith("/v1/runner-sessions/") and path.endswith("/report"):
            context = self._context(require_actor=True)
            if context is None:
                return
            body = self._body()
            if body is None:
                return
            session_id = unquote(path[len("/v1/runner-sessions/") : -len("/report")].strip("/"))
            result = self.server.service.report_runner_session(session_id, body, context)
            status = 200 if result.get("status") == "success" else 404 if result.get("status") == "unknown" else 409 if result.get("error_code") == "runner_session_closed" else 422
            self._respond(status, result)
            return

        if path.startswith("/v1/runner-sessions/") and path.endswith("/patch-artifacts"):
            context = self._context(require_actor=True)
            if context is None:
                return
            body = self._body()
            if body is None:
                return
            session_id = unquote(path[len("/v1/runner-sessions/") : -len("/patch-artifacts")].strip("/"))
            result = self.server.service.create_patch_artifact(session_id, body, context)
            status = 201 if result.get("status") == "success" else 404 if result.get("status") == "unknown" else 409 if result.get("error_code") in ("patch_application_not_allowed", "runner_session_closed") else 422
            self._respond(status, result)
            return

        if path.startswith("/v1/runner-sessions/") and path.endswith("/validation-reports"):
            context = self._context(require_actor=True)
            if context is None:
                return
            body = self._body()
            if body is None:
                return
            session_id = unquote(path[len("/v1/runner-sessions/") : -len("/validation-reports")].strip("/"))
            result = self.server.service.create_validation_report(session_id, body, context)
            status = 201 if result.get("status") == "success" else 404 if result.get("status") == "unknown" else 409 if result.get("error_code") == "runner_session_closed" else 422
            self._respond(status, result)
            return

        if path.startswith("/v1/evidence/sources/") and path.endswith("/collect"):
            context = self._context(require_actor=True)
            if context is None:
                return
            body = self._body()
            if body is None:
                return
            adapter_id = path[len("/v1/evidence/sources/") : -len("/collect")].strip("/")
            result = self.server.service.collect_external_evidence(adapter_id, body, context)
            if result.get("status") == "success":
                status = 201
            elif result.get("status") == "unknown":
                status = 503
            else:
                status = 422
            self._respond(status, result)
            return

        if path == "/v1/identity/resolve":
            context = self._context(require_actor=False)
            if context is None:
                return
            body = self._body()
            if body is None:
                return
            subject_id = body.get("subject_id", "self")
            if not isinstance(subject_id, str):
                self._respond(422, {"error": "subject_id_must_be_string"})
                return
            github_repository = body.get("github_repository")
            if github_repository is not None:
                actor = dict(context.actor)
                actor["github_repository"] = github_repository
                context = AdapterContext(
                    request_id=context.request_id,
                    actor=actor,
                    evidence_ids=context.evidence_ids,
                    read_only=context.read_only,
                )
            result = self.server.service.resolve_identity(subject_id, context)
            if result.get("status") == "success":
                status = 200
            elif result.get("status") == "unknown":
                status = 503
            else:
                status = 422
            self._respond(status, result)
            return

        self._respond(404, {"error": "not_found", "path": path})

    def _context(self, require_actor: bool) -> AdapterContext | None:
        actor_id = self.headers.get("X-AINE-Actor")
        if require_actor and not actor_id:
            self._respond(401, {"error": "actor_required", "reason": "send X-AINE-Actor for this route"})
            return None
        roles = tuple(value for value in self.headers.get("X-AINE-Roles", "").split(",") if value)
        teams = tuple(value for value in self.headers.get("X-AINE-Teams", "").split(",") if value)
        actor = {
            "id": actor_id or "anonymous",
            "subject_id": actor_id or "anonymous",
            "roles": roles,
            "teams": teams,
            # The reference transport does not verify X-AINE-Actor; records say so.
            "source": "header",
        }
        return AdapterContext(
            request_id=self.headers.get("X-Request-ID", f"http.{uuid4().hex}"),
            actor=actor,
        )

    def _body(self) -> Mapping[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            value = json.loads(raw or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._respond(400, {"error": "invalid_json"})
            return None
        if not isinstance(value, Mapping):
            self._respond(400, {"error": "request_body_must_be_object"})
            return None
        return value

    def do_OPTIONS(self) -> None:  # noqa: N802
        if not self.server.cors_origin:
            self.send_error(501, "Unsupported method ('OPTIONS')")
            return
        self.send_response(204)
        self._send_cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-AINE-Actor")
        self.send_header("Access-Control-Max-Age", "86400")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_cors_headers(self) -> None:
        if self.server.cors_origin:
            self.send_header("Access-Control-Allow-Origin", self.server.cors_origin)
            self.send_header("Vary", "Origin")

    def _respond(self, status: int, value: Any) -> None:
        body = _json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        if self.server.log_requests:
            super().log_message(format, *args)


class ControlPlaneHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        service: ControlPlaneService,
        log_requests: bool = False,
        cors_origin: str | None = None,
    ) -> None:
        super().__init__(address, _Handler)
        self.service = service
        self.log_requests = log_requests
        self.cors_origin = cors_origin


def serve(
    service: ControlPlaneService,
    host: str = "127.0.0.1",
    port: int = 8787,
    log_requests: bool = False,
    cors_origin: str | None = None,
) -> None:
    """Run the reference self-hosted HTTP transport until interrupted.

    ``cors_origin`` opts in to cross-origin browser access for exactly one
    origin (e.g. a UI build served from another port). Off by default: the
    reference transport stays same-origin/loopback unless the operator names
    the origin explicitly. It is not a substitute for the authentication,
    TLS, and authorization boundary a non-loopback deployment requires.
    """

    server = ControlPlaneHTTPServer((host, port), service, log_requests=log_requests, cors_origin=cors_origin)
    try:
        server.serve_forever()
    finally:
        server.server_close()
