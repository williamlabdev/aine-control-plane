from __future__ import annotations

from typing import Any, Iterable, Mapping

from .approval import ApprovalWorkflow
from .attribution import actor_attribution_report
from .change_requests import ChangeRequestWorkflow
from .contracts import AdapterContext, CONTRACT_VERSION, EvidenceSourceAdapter, IdentityAdapter
from .governance import authorize, evaluate_policy
from .portfolio import PortfolioRegistry
from .retention import evaluate_store_retention
from .remediation import RemediationWorkflow
from .runner import RunnerWorkflow
from .store import LocalRecordStore


SERVICE_SCHEMA = "aine.control-plane.service.v1"


class ControlPlaneService:
    """Provider-neutral application service for the self-hosted core."""

    def __init__(
        self,
        store: LocalRecordStore,
        authorization_rules: Iterable[Mapping[str, Any]] = (),
        identity_adapter: IdentityAdapter | None = None,
        evidence_sources: Mapping[str, EvidenceSourceAdapter] | None = None,
        attribution_owner: str | None = None,
    ) -> None:
        self.store = store
        self.portfolio = PortfolioRegistry(store)
        self.approvals = ApprovalWorkflow(store)
        self.change_requests = ChangeRequestWorkflow(store, self.approvals)
        self.remediation = RemediationWorkflow(store, self.approvals)
        self.runner = RunnerWorkflow(store, self.remediation)
        self.authorization_rules = tuple(dict(rule) for rule in authorization_rules)
        self.identity_adapter = identity_adapter
        self.evidence_sources = dict(evidence_sources or {})
        self.attribution_owner = attribution_owner

    def contract(self) -> Mapping[str, Any]:
        return {
            "schema": SERVICE_SCHEMA,
            "contract_version": CONTRACT_VERSION,
            "read_only": True,
            "capabilities": [
                "self_hosted_http",
                "local_append_only_persistence",
                "evidence",
                "external_evidence_collection",
                "external_identity_resolution",
                "authenticated_adapter_bootstrap",
                "credential_provider_boundary",
                "portfolio_snapshot_ingest",
                "impact",
                "portfolio_relationships",
                "portfolio_source_of_truth",
                "policy_advisory",
                "policy_enforced",
                "authorization_rbac_abac",
                "approval_workflow",
                "change_requests",
                "remediation_plans",
                "dry_run_execution_requests",
                "external_local_runner_protocol",
                "runner_sessions",
                "patch_artifacts",
                "validation_reports",
                "audit_events",
                "actor_attribution_report",
                "retention_evaluation",
                "evidence_export",
            ],
        }

    def health(self) -> Mapping[str, Any]:
        return {
            "schema": "aine.control-plane.health.v1",
            "status": "ok",
            "service": "aine-control-plane",
            "contract_version": CONTRACT_VERSION,
            "persistence": "local-record-store",
            "read_only": True,
        }

    def put_evidence(self, record: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]:
        return self.store.put(record, context, record_type="evidence")

    def get_evidence(self, record_id: str) -> Mapping[str, Any] | None:
        return self.store.get(record_id)

    def list_evidence(self) -> list[Mapping[str, Any]]:
        return self.store.list_records("evidence")

    def adapters(self) -> list[Mapping[str, Any]]:
        result = []
        configured = list(self.evidence_sources.values())
        if self.identity_adapter is not None:
            configured.append(self.identity_adapter)
        for adapter in configured:
            config = adapter.config.as_dict() if hasattr(adapter, "config") else {}
            if config.get("credential_refs"):
                config["credential_refs"] = ["<configured>"]
            result.append({"metadata": adapter.metadata.as_dict(), "config": config})
        return result

    def collect_external_evidence(
        self,
        adapter_id: str,
        request: Mapping[str, Any],
        context: AdapterContext,
    ) -> Mapping[str, Any]:
        adapter = self.evidence_sources.get(adapter_id)
        if adapter is None:
            return {
                "schema": "aine.control-plane.adapter-outcome.v1",
                "status": "unknown",
                "adapter_id": adapter_id,
                "operation": "collect",
                "request_id": context.request_id,
                "read_only": context.read_only,
                "reasons": ["evidence source adapter is not configured"],
            }
        result = adapter.collect(request, context)
        if result.get("status") != "success":
            return result
        evidence = result.get("result", {}).get("evidence")
        if not isinstance(evidence, Mapping):
            return {
                "schema": "aine.control-plane.adapter-outcome.v1",
                "status": "failure",
                "adapter_id": adapter_id,
                "operation": "collect",
                "request_id": context.request_id,
                "read_only": context.read_only,
                "error_code": "adapter_evidence_missing",
                "reasons": ["successful adapter outcome did not include an evidence record"],
            }
        stored = self.store.put(evidence, context, record_type="evidence")
        response = dict(result)
        response_result = dict(result.get("result", {}))
        response_result["stored"] = stored
        response["result"] = response_result
        return response

    def ingest_snapshot(self, snapshot: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]:
        return self.portfolio.ingest_snapshot(snapshot, context)

    def projects(self, *, include_retired: bool = False) -> list[Mapping[str, Any]]:
        return self.portfolio.projects(include_retired=include_retired)

    def get_project(self, project_id: str) -> Mapping[str, Any] | None:
        return self.portfolio.get_project(project_id)

    def impact(self, project_id: str) -> Mapping[str, Any]:
        return self.portfolio.impact(project_id)

    def relationships(
        self,
        project_id: str | None = None,
        relationship_type: str | None = None,
        status: str | None = None,
        *,
        include_retired: bool = False,
    ) -> list[Mapping[str, Any]]:
        return self.portfolio.relationships(project_id, relationship_type, status, include_retired=include_retired)

    def source_of_truth(
        self,
        domain: str | None = None,
        project_id: str | None = None,
    ) -> list[Mapping[str, Any]]:
        return self.portfolio.source_of_truth(domain, project_id)

    def portfolio_provenance(self) -> Mapping[str, Any]:
        snapshot_ids = self.portfolio.snapshot_ids()
        return {
            "snapshot_ids": snapshot_ids,
            "snapshot_count": len(snapshot_ids),
            "latest_snapshot_id": snapshot_ids[-1] if snapshot_ids else None,
        }

    def list_change_requests(self) -> list[Mapping[str, Any]]:
        return self.change_requests.list()

    def get_change_request(self, change_id: str) -> Mapping[str, Any] | None:
        return self.change_requests.get(change_id)

    def create_change_request(
        self,
        request: Mapping[str, Any],
        context: AdapterContext,
    ) -> Mapping[str, Any]:
        return self.change_requests.create(request, context)

    def submit_change_request(self, change_id: str, context: AdapterContext) -> Mapping[str, Any]:
        return self.change_requests.submit(change_id, context)

    def list_remediation_plans(self) -> list[Mapping[str, Any]]:
        return self.remediation.list_plans()

    def get_remediation_plan(self, plan_id: str) -> Mapping[str, Any] | None:
        return self.remediation.get_plan(plan_id)

    def create_remediation_plan(self, request: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]:
        return self.remediation.create_plan(request, context)

    def submit_remediation_plan(self, plan_id: str, context: AdapterContext) -> Mapping[str, Any]:
        return self.remediation.submit_plan(plan_id, context)

    def request_remediation_dry_run(self, plan_id: str, context: AdapterContext) -> Mapping[str, Any]:
        return self.remediation.request_dry_run(plan_id, context)

    def list_remediation_executions(self) -> list[Mapping[str, Any]]:
        return self.remediation.list_executions()

    def get_remediation_execution(self, execution_id: str) -> Mapping[str, Any] | None:
        return self.remediation.get_execution(execution_id)

    def report_remediation_execution(
        self,
        execution_id: str,
        request: Mapping[str, Any],
        context: AdapterContext,
    ) -> Mapping[str, Any]:
        return self.remediation.report_execution(execution_id, request, context)

    def list_runner_sessions(self) -> list[Mapping[str, Any]]:
        return self.runner.list_sessions()

    def get_runner_session(self, session_id: str) -> Mapping[str, Any] | None:
        return self.runner.get_session(session_id)

    def create_runner_session(
        self,
        execution_id: str,
        request: Mapping[str, Any],
        context: AdapterContext,
    ) -> Mapping[str, Any]:
        return self.runner.create_session(execution_id, request, context)

    def report_runner_session(
        self,
        session_id: str,
        request: Mapping[str, Any],
        context: AdapterContext,
    ) -> Mapping[str, Any]:
        return self.runner.report_session(session_id, request, context)

    def list_patch_artifacts(self) -> list[Mapping[str, Any]]:
        return self.runner.list_patch_artifacts()

    def get_patch_artifact(self, patch_id: str) -> Mapping[str, Any] | None:
        return self.runner.get_patch_artifact(patch_id)

    def create_patch_artifact(
        self,
        session_id: str,
        request: Mapping[str, Any],
        context: AdapterContext,
    ) -> Mapping[str, Any]:
        return self.runner.create_patch_artifact(session_id, request, context)

    def list_validation_reports(self) -> list[Mapping[str, Any]]:
        return self.runner.list_validation_reports()

    def get_validation_report(self, report_id: str) -> Mapping[str, Any] | None:
        return self.runner.get_validation_report(report_id)

    def create_validation_report(
        self,
        session_id: str,
        request: Mapping[str, Any],
        context: AdapterContext,
    ) -> Mapping[str, Any]:
        return self.runner.create_validation_report(session_id, request, context)

    def evaluate_policy(
        self,
        policy: Mapping[str, Any],
        checks: Iterable[Mapping[str, Any]] | Mapping[str, Mapping[str, Any]],
        context: AdapterContext,
        mode: str | None = None,
    ) -> Mapping[str, Any]:
        decision = evaluate_policy(policy, checks, context, mode)
        self.store.append_event("policy.evaluated", str(decision["policy_id"]), decision, context)
        return decision

    def authorize(
        self,
        subject: Mapping[str, Any],
        action: str,
        resource: str,
        context: AdapterContext,
    ) -> Mapping[str, Any]:
        decision = authorize(subject, self.authorization_rules, action, resource, context)
        self.store.append_event("authorization.evaluated", resource, decision, context)
        return decision

    def resolve_identity(self, subject_id: str, context: AdapterContext) -> Mapping[str, Any]:
        if self.identity_adapter is None:
            return {
                "schema": "aine.control-plane.adapter-outcome.v1",
                "status": "unknown",
                "adapter_id": "service.identity",
                "operation": "resolve",
                "request_id": context.request_id,
                "read_only": context.read_only,
                "result": {"subject_id": subject_id},
                "reasons": ["no identity adapter configured"],
            }
        return self.identity_adapter.resolve(subject_id, context)

    def create_approval(self, request: Mapping[str, Any], context: AdapterContext) -> Mapping[str, Any]:
        return self.approvals.create(request, context)

    def decide_approval(
        self,
        approval_id: str,
        decision: str,
        reason: str,
        context: AdapterContext,
    ) -> Mapping[str, Any]:
        return self.approvals.decide(approval_id, decision, reason, context)

    def get_approval(self, approval_id: str) -> Mapping[str, Any] | None:
        return self.approvals.get(approval_id)

    def retention(self, policy: Mapping[str, Any]) -> Mapping[str, Any]:
        return evaluate_store_retention(self.store, policy)

    def audit_events(self, aggregate_id: str | None = None) -> list[Mapping[str, Any]]:
        return self.store.list_events(aggregate_id)

    def actor_attribution(self, day: str | None = None) -> Mapping[str, Any]:
        return actor_attribution_report(self.store.list_rows(), self.attribution_owner, day)

    def export(self, destination: str) -> Mapping[str, Any]:
        return self.store.export(destination)
