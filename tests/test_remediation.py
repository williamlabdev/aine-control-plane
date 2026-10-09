from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import Request, urlopen

from aine_control_plane.contracts import AdapterContext
from aine_control_plane.remediation import (
    EXECUTION_REQUEST_SCHEMA,
    REMEDIATION_PLAN_SCHEMA,
    RemediationWorkflow,
    validate_execution_request,
    validate_remediation_plan,
)
from aine_control_plane.service import ControlPlaneService
from aine_control_plane.server import ControlPlaneHTTPServer
from aine_control_plane.store import LocalRecordStore


FIXTURE_DIR = Path(__file__).parents[1] / "aine_control_plane" / "fixtures"


class RemediationWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.developer = AdapterContext(
            "remediation-test",
            actor={"id": "agent.codex", "roles": ["developer"], "teams": ["platform"]},
        )
        self.approver = AdapterContext(
            "remediation-approval",
            actor={"id": "human.william", "roles": ["approver"], "teams": ["platform"], "source": "token"},
        )

    def _plan_request(self):
        return {
            "plan_id": "remediation.plan.test",
            "title": "Repair unresolved API dependency evidence",
            "rationale": "Turn the unresolved relationship into an evidence-backed change.",
            "finding": {"finding_id": "DEP-001", "severity": "medium", "summary": "Dependency evidence is unresolved."},
            "scope": {"project_ids": ["reference.consumer"]},
            "strategy": {"kind": "evidence_update", "description": "Prepare a scoped change in an isolated runner."},
            "validation": {"required_checks": ["registry.validate", "preflight"]},
            "acceptance_criteria": ["Validation evidence is attached."],
            "evidence_ids": ["evidence.preflight.1"],
            "risk": "medium",
            "approval_required": True,
        }

    def test_fixtures_and_schema_validation(self):
        plan = json.loads((FIXTURE_DIR / "remediation_plan.json").read_text(encoding="utf-8"))
        execution = json.loads((FIXTURE_DIR / "execution_request.json").read_text(encoding="utf-8"))
        self.assertEqual(plan["schema"], REMEDIATION_PLAN_SCHEMA)
        self.assertEqual(execution["schema"], EXECUTION_REQUEST_SCHEMA)
        self.assertEqual(validate_remediation_plan(plan), [])
        self.assertEqual(validate_execution_request(execution), [])

    def test_plan_requires_approval_before_dry_run(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalRecordStore(Path(directory) / "control-plane.sqlite")
            service = ControlPlaneService(store)
            created = service.create_remediation_plan(self._plan_request(), self.developer)
            self.assertEqual(created["status"], "success")
            submitted = service.submit_remediation_plan("remediation.plan.test", self.developer)
            self.assertEqual(submitted["status"], "success")
            approval_id = submitted["result"]["plan"]["approval_id"]
            blocked = service.request_remediation_dry_run("remediation.plan.test", self.developer)
            self.assertEqual(blocked["status"], "failure")
            self.assertEqual(blocked["error_code"], "remediation_approval_required")

            decision = service.decide_approval(approval_id, "approve", "scope and validation reviewed", self.approver)
            self.assertEqual(decision["status"], "success")
            self.assertEqual(service.list_remediation_plans()[0]["status"], "approved")
            requested = service.request_remediation_dry_run("remediation.plan.test", self.developer)
            self.assertEqual(requested["status"], "success")
            execution_id = requested["result"]["execution"]["execution_id"]
            self.assertEqual(requested["result"]["execution"]["mode"], "dry_run")
            self.assertFalse(requested["result"]["execution"]["mutation_scope"]["source_repositories"])

            reported = service.report_remediation_execution(
                execution_id,
                {"status": "completed", "result": {"summary": "Validation plan prepared"}, "evidence_ids": ["evidence.validation.1"]},
                self.developer,
            )
            self.assertEqual(reported["status"], "success")
            self.assertEqual(service.get_remediation_execution(execution_id)["status"], "completed")
            event_types = [event["event_type"] for event in store.list_events()]
            self.assertEqual(
                event_types,
                [
                    "remediation.plan.created",
                    "remediation.plan.submitted",
                    "approval.requested",
                    "approval.decided",
                    "remediation.execution.requested",
                    "remediation.execution.completed",
                ],
            )

    def test_paths_and_mutating_execution_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalRecordStore(Path(directory) / "control-plane.sqlite")
            workflow = RemediationWorkflow(store)
            leaked = self._plan_request()
            leaked["scope"] = {"project_ids": ["reference.consumer"], "path": "/Users/example/private"}
            result = workflow.create_plan(leaked, self.developer)
            self.assertEqual(result["status"], "failure")
            self.assertEqual(result["error_code"], "invalid_remediation_plan")

            invalid_execution = json.loads((FIXTURE_DIR / "execution_request.json").read_text(encoding="utf-8"))
            invalid_execution["mutation_scope"]["git"] = True
            self.assertTrue(validate_execution_request(invalid_execution))

    def test_no_approval_plan_can_request_dry_run(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalRecordStore(Path(directory) / "control-plane.sqlite")
            service = ControlPlaneService(store)
            request = self._plan_request()
            request["plan_id"] = "remediation.plan.no-approval"
            request["risk"] = "low"
            request["approval_required"] = False
            self.assertEqual(service.create_remediation_plan(request, self.developer)["status"], "success")
            self.assertEqual(service.submit_remediation_plan(request["plan_id"], self.developer)["status"], "success")
            self.assertEqual(service.list_remediation_plans()[0]["status"], "approved")
            self.assertEqual(service.request_remediation_dry_run(request["plan_id"], self.developer)["status"], "success")

    def test_non_low_risk_plan_cannot_disable_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalRecordStore(Path(directory) / "control-plane.sqlite")
            workflow = RemediationWorkflow(store)
            request = self._plan_request()
            request["plan_id"] = "remediation.plan.unsafe-no-approval"
            request["approval_required"] = False
            result = workflow.create_plan(request, self.developer)
            self.assertEqual(result["status"], "failure")
            self.assertEqual(result["error_code"], "invalid_remediation_plan")
            self.assertIn("approval is required", result["reasons"][0])

    def test_http_routes_expose_plan_and_dry_run_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalRecordStore(Path(directory) / "control-plane.sqlite")
            server = ControlPlaneHTTPServer(("127.0.0.1", 0), ControlPlaneService(store))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            request = self._plan_request()
            request["plan_id"] = "remediation.plan.http"
            request["risk"] = "low"
            request["approval_required"] = False
            try:
                create = Request(
                    f"{base}/v1/remediation-plans",
                    data=json.dumps(request).encode("utf-8"),
                    headers={"Content-Type": "application/json", "X-AINE-Actor": "agent.codex"},
                    method="POST",
                )
                with urlopen(create) as response:
                    self.assertEqual(json.loads(response.read())["status"], "success")

                with urlopen(f"{base}/v1/remediation-plans") as response:
                    plans = json.loads(response.read())
                self.assertEqual(plans["plans"][0]["status"], "draft")

                submit = Request(
                    f"{base}/v1/remediation-plans/remediation.plan.http/submit",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-AINE-Actor": "agent.codex"},
                    method="POST",
                )
                with urlopen(submit) as response:
                    submitted = json.loads(response.read())
                self.assertEqual(submitted["result"]["plan"]["status"], "approved")

                execute = Request(
                    f"{base}/v1/remediation-plans/remediation.plan.http/execution",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-AINE-Actor": "agent.codex"},
                    method="POST",
                )
                with urlopen(execute) as response:
                    execution = json.loads(response.read())
                self.assertEqual(execution["result"]["execution"]["mode"], "dry_run")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
