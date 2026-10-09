from __future__ import annotations

import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from aine_control_plane.approval import ApprovalWorkflow
from aine_control_plane.contracts import AdapterContext
from aine_control_plane.governance import authorize, evaluate_policy
from aine_control_plane.portfolio import PortfolioRegistry, validate_snapshot
from aine_control_plane.retention import evaluate_store_retention
from aine_control_plane.server import ControlPlaneHTTPServer
from aine_control_plane.service import ControlPlaneService
from aine_control_plane.store import LocalRecordStore
from aine_control_plane.validation import validate_authorization_decision, validate_outcome, validate_policy_decision


FIXTURE_DIR = Path(__file__).parents[1] / "aine_control_plane" / "fixtures"


class V1CoreTests(unittest.TestCase):
    def setUp(self):
        self.context = AdapterContext(
            "request-v1",
            actor={"id": "agent.codex", "roles": ["approver"], "teams": ["platform"], "source": "token"},
        )

    def test_policy_advisory_and_enforced_modes_preserve_unknowns(self):
        policy = {"policy_id": "policy.release", "required_checks": ["tests", "security"]}
        checks = [
            {"check_id": "tests", "status": "pass", "evidence_ids": ["evidence.tests"]},
            {"check_id": "security", "status": "fail", "evidence_ids": ["evidence.security"]},
        ]
        advisory = evaluate_policy(policy, checks, self.context)
        self.assertEqual(validate_policy_decision(advisory), [])
        self.assertEqual(advisory["status"], "fail")
        self.assertFalse(advisory["blocked"])
        self.assertEqual(advisory["evidence_ids"], ["evidence.tests", "evidence.security"])

        enforced = evaluate_policy(policy, checks, self.context, mode="enforced")
        self.assertEqual(enforced["status"], "fail")
        self.assertTrue(enforced["blocked"])

        unknown = evaluate_policy(policy, [{"check_id": "tests", "status": "pass"}], self.context, mode="enforced")
        self.assertEqual(unknown["status"], "unknown")
        self.assertTrue(unknown["blocked"])

    def test_rbac_and_abac_authorization(self):
        subject = {
            "subject_id": "agent.codex",
            "roles": ["developer"],
            "teams": ["platform"],
            "attributes": {"environment": "staging"},
        }
        rules = [
            {"rule_id": "rule.deploy-staging", "effect": "allow", "action": "deploy", "resource": "service/*", "roles": ["developer"], "attributes": {"environment": "staging"}},
            {"rule_id": "rule.deny-prod", "effect": "deny", "action": "deploy", "resource": "service/production"},
        ]
        allowed = authorize(subject, rules, "deploy", "service/checkout", self.context)
        self.assertEqual(validate_authorization_decision(allowed), [])
        self.assertEqual(allowed["status"], "allow")
        denied = authorize(subject, rules, "deploy", "service/production", self.context)
        self.assertEqual(denied["status"], "deny")
        unknown = authorize({"subject_id": "unknown", "roles": ["developer"], "attributes": {}}, rules, "deploy", "service/checkout", self.context)
        self.assertEqual(unknown["status"], "unknown")

    def test_store_rejects_nonportable_records_and_event_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalRecordStore(Path(directory) / "control-plane.sqlite")
            record = {"schema": "aine.evidence.v1", "evidence_id": "evidence.path", "claims": {"path": "/Users/example/private.txt"}}

            rejected = store.put(record, self.context)
            self.assertEqual(rejected["status"], "failure")
            self.assertEqual(rejected["error_code"], "invalid_record")

            event = store.append_event("evidence.recorded", "evidence.path", record, self.context)
            self.assertEqual(event["status"], "failure")
            self.assertEqual(event["error_code"], "invalid_event_payload")

            # The append-only trail is what this product sells; a rejected
            # payload must leave no trace behind it.
            self.assertEqual(store.list_events(), [])

    def test_append_event_requires_a_read_only_request_context(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalRecordStore(Path(directory) / "control-plane.sqlite")
            record = {"schema": "aine.evidence.v1", "evidence_id": "evidence.context", "claims": {"status": "pass"}}

            anonymous = store.append_event("evidence.recorded", "evidence.context", record, AdapterContext(""))
            self.assertEqual(anonymous["status"], "failure")
            self.assertEqual(anonymous["error_code"], "invalid_context")

            writable = AdapterContext("request-v1", actor=self.context.actor, read_only=False)
            mutable = store.append_event("evidence.recorded", "evidence.context", record, writable)
            self.assertEqual(mutable["status"], "failure")
            self.assertEqual(mutable["error_code"], "read_only_context_required")

            self.assertEqual(store.list_events(), [])

    def test_store_approval_retention_and_portfolio_are_append_only(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalRecordStore(Path(directory) / "control-plane.sqlite", clock=lambda: "2026-01-10T00:00:00+00:00")
            record = {"schema": "aine.evidence.v1", "evidence_id": "evidence.store", "claims": {"status": "pass"}}
            first = store.put(record, self.context)
            self.assertEqual(first["status"], "success")
            duplicate = store.put(record, self.context)
            self.assertTrue(duplicate["result"]["duplicate"])
            conflict = store.put({**record, "claims": {"status": "fail"}}, self.context)
            self.assertEqual(conflict["status"], "conflict")
            self.assertEqual(validate_outcome(conflict), [])

            store.append_event("evidence.recorded", "evidence.store", record, self.context)
            exported = store.export(Path(directory) / "export.json")
            self.assertEqual(exported["record_count"], 1)
            self.assertEqual(len(store.list_events()), 1)

            retention = evaluate_store_retention(
                store,
                {"retain_days": 1},
                now=lambda: datetime(2026, 1, 12, tzinfo=timezone.utc),
            )
            self.assertEqual(retention["decisions"][0]["status"], "review")

            portfolio = PortfolioRegistry(store)
            snapshot = json.loads((FIXTURE_DIR / "registry_snapshot.json").read_text(encoding="utf-8"))
            leaked = json.loads(json.dumps(snapshot))
            leaked["artifacts"][0]["path"] = "/Users/example/private/api.yaml"
            self.assertEqual(portfolio.ingest_snapshot(leaked, self.context)["status"], "failure")
            ingested = portfolio.ingest_snapshot(snapshot, self.context)
            self.assertEqual(ingested["status"], "success")
            self.assertEqual(portfolio.get_project("reference.provider")["name"], "provider")
            impact = portfolio.impact("reference.provider")
            self.assertEqual(impact["affected_projects"][0]["project_id"], "reference.consumer")

            portable_relative = json.loads(json.dumps(snapshot))
            portable_relative["snapshot_id"] = "snapshot.relative-paths"
            portable_relative["projects"][0]["evidence"] = ["./provider/pyproject.toml"]
            portable_relative["artifacts"][0]["workspace_path"] = "./provider/api.yaml"
            portable_relative["artifacts"][0]["evidence"] = ["../aine-registry/registry/schema/registry.v1.schema.json"]
            portable_relative["dependencies"][0]["reference"] = {"reference": "../aine-registry/README.md"}
            relative_ingest = portfolio.ingest_snapshot(portable_relative, self.context)
            self.assertEqual(relative_ingest["status"], "success")
            structured_edge = next(edge for edge in portfolio.relationships() if edge["dependency_id"] == "dependency.reference.1")
            self.assertIsInstance(structured_edge["evidence"], dict)
            self.assertNotIn("evidence_refs", structured_edge)

            windows_path = json.loads(json.dumps(snapshot))
            windows_path["snapshot_id"] = "snapshot.windows-path"
            windows_path["artifacts"][0]["path"] = "C:\\Users\\private\\api.yaml"
            self.assertEqual(portfolio.ingest_snapshot(windows_path, self.context)["status"], "failure")

            unc_path = json.loads(json.dumps(snapshot))
            unc_path["snapshot_id"] = "snapshot.unc-path"
            unc_path["artifacts"][0]["path"] = "\\\\server\\share\\api.yaml"
            self.assertEqual(portfolio.ingest_snapshot(unc_path, self.context)["status"], "failure")

            file_uri = json.loads(json.dumps(snapshot))
            file_uri["snapshot_id"] = "snapshot.file-uri"
            file_uri["artifacts"][0]["path"] = "file:/Users/private/api.yaml"
            self.assertEqual(portfolio.ingest_snapshot(file_uri, self.context)["status"], "failure")

    def test_approval_workflow_requires_role_and_reaches_approved(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalRecordStore(Path(directory) / "control-plane.sqlite")
            workflow = ApprovalWorkflow(store)
            request = {
                "approval_id": "approval.release.1",
                "subject": {"change_id": "change.1"},
                "scope": {"project_id": "reference.consumer"},
                "requested_by": "agent.codex",
                "required_approvals": 1,
                "required_roles": ["approver"],
            }
            created = workflow.create(request, self.context)
            self.assertEqual(created["status"], "success")
            approved = workflow.decide("approval.release.1", "approve", "validated", self.context)
            self.assertEqual(approved["status"], "success")
            self.assertEqual(workflow.get("approval.release.1")["status"], "approved")

            unauthorized = AdapterContext("request-unauthorized", actor={"id": "agent.other", "roles": ["developer"], "source": "token"})
            rejected = workflow.decide("approval.release.1", "reject", "late", unauthorized)
            self.assertEqual(rejected["status"], "failure")

    def test_portfolio_surface_queries_dependencies_relationships_and_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            timestamps = iter(
                [
                    "2026-01-01T00:00:00+00:00",
                    "2026-01-01T00:00:01+00:00",
                    "2026-01-02T00:00:00+00:00",
                    "2026-01-02T00:00:01+00:00",
                ]
            )
            store = LocalRecordStore(
                Path(directory) / "control-plane.sqlite",
                clock=lambda: next(timestamps, "2026-01-03T00:00:00+00:00"),
            )
            portfolio = PortfolioRegistry(store)
            snapshot = json.loads((FIXTURE_DIR / "registry_semantics_snapshot.json").read_text(encoding="utf-8"))

            ingested = portfolio.ingest_snapshot(snapshot, self.context)
            self.assertEqual(ingested["status"], "success")

            relationships = portfolio.relationships()
            self.assertEqual(
                {edge.get("dependency_id") for edge in relationships},
                {"dep.polyrepo.cross-root", "dep.polyrepo.web-app", "rel.polyrepo.service-client"},
            )
            self.assertTrue(all(edge.get("observed_snapshot_id") == "snapshot.polyrepo.semantic.1" for edge in relationships))
            cross_root = portfolio.relationships(project_id="core.checkout-service", status="planned")
            self.assertEqual([edge["dependency_id"] for edge in cross_root], ["dep.polyrepo.cross-root"])
            explicit = portfolio.relationships(relationship_type="service_client")
            self.assertEqual([edge["dependency_id"] for edge in explicit], ["rel.polyrepo.service-client"])
            self.assertEqual(explicit[0]["evidence"], ["web-app/.aine/registry.json"])
            runtime_edges = portfolio.relationships(relationship_type="runtime_api")
            self.assertEqual(
                {edge["dependency_id"] for edge in runtime_edges},
                {"dep.polyrepo.cross-root", "dep.polyrepo.web-app"},
            )

            source_rules = portfolio.source_of_truth(domain="checkout.api")
            self.assertEqual(len(source_rules), 1)
            self.assertEqual(source_rules[0]["authority"]["project_id"], "core.checkout-service")
            self.assertEqual(source_rules[0]["observed_snapshot_id"], "snapshot.polyrepo.semantic.1")
            self.assertEqual(
                portfolio.source_of_truth(project_id="side-projects.content-tool"),
                [],
            )
            impact = portfolio.impact("core.checkout-service")
            self.assertEqual(impact["source_of_truth"], source_rules)
            self.assertEqual(portfolio.snapshot_ids(), ["snapshot.polyrepo.semantic.1"])

            updated = json.loads(json.dumps(snapshot))
            updated["snapshot_id"] = "snapshot.polyrepo.semantic.2"
            updated["dependencies"][0]["status"] = "active"
            updated["dependencies"][0]["evidence"].append("content-tool/.aine/registry.v2.json")
            updated["relationships"][0]["status"] = "conflict"
            updated["relationships"][0]["evidence"].append("web-app/.aine/registry.v2.json")
            updated["source_of_truth"][0]["authority"]["project_id"] = "core.web-app"
            updated["source_of_truth"][0]["status"] = "conflict"
            updated["source_of_truth"][0]["evidence"].append("web-app/.aine/registry.v2.json")
            self.assertEqual(portfolio.ingest_snapshot(updated, self.context)["status"], "success")
            active_edges = portfolio.relationships(project_id="core.checkout-service", status="active")
            self.assertEqual(
                [edge["dependency_id"] for edge in active_edges],
                ["dep.polyrepo.cross-root", "dep.polyrepo.web-app"],
            )
            current_cross_root = [edge for edge in active_edges if edge.get("dependency_id") == "dep.polyrepo.cross-root"]
            self.assertEqual([edge["dependency_id"] for edge in current_cross_root], ["dep.polyrepo.cross-root"])
            self.assertEqual(
                current_cross_root[0]["evidence"],
                ["content-tool/.aine/registry.json", "content-tool/.aine/registry.v2.json"],
            )
            self.assertEqual(current_cross_root[0]["observed_snapshot_id"], "snapshot.polyrepo.semantic.2")
            self.assertEqual(
                current_cross_root[0]["evidence_refs"],
                ["content-tool/.aine/registry.json", "content-tool/.aine/registry.v2.json"],
            )
            self.assertEqual(portfolio.relationships(status="planned"), [])
            self.assertEqual(portfolio.relationships(relationship_type="service_client")[0]["status"], "conflict")
            current_rule = portfolio.source_of_truth(domain="checkout.api")[0]
            self.assertEqual(current_rule["authority"]["project_id"], "core.web-app")
            self.assertEqual(current_rule["observed_snapshot_id"], "snapshot.polyrepo.semantic.2")
            self.assertEqual(
                current_rule["evidence_refs"],
                ["checkout-service/.aine/registry.json", "web-app/.aine/registry.v2.json"],
            )
            self.assertEqual(portfolio.source_of_truth(project_id="core.checkout-service"), [])
            self.assertEqual(portfolio.snapshot_ids(), ["snapshot.polyrepo.semantic.1", "snapshot.polyrepo.semantic.2"])

            malformed = json.loads(json.dumps(snapshot))
            malformed["snapshot_id"] = "snapshot.invalid-relationship"
            malformed["relationships"] = [{"source": {}, "target": {}, "evidence": ["ok"]}]
            rejected = portfolio.ingest_snapshot(malformed, self.context)
            self.assertEqual(rejected["status"], "failure")
            self.assertEqual(rejected["error_code"], "invalid_snapshot")

            malformed_dependency = json.loads(json.dumps(snapshot))
            malformed_dependency["snapshot_id"] = "snapshot.invalid-dependency"
            malformed_dependency["dependencies"] = [{"dependency_id": "bad"}]
            self.assertEqual(portfolio.ingest_snapshot(malformed_dependency, self.context)["status"], "failure")

            malformed_schema = json.loads(json.dumps(snapshot))
            malformed_schema["snapshot_id"] = 42
            malformed_schema["schema"] = "aine.registry.other"
            self.assertEqual(portfolio.ingest_snapshot(malformed_schema, self.context)["status"], "failure")

            malformed_types = json.loads(json.dumps(snapshot))
            malformed_types["snapshot_id"] = "snapshot.invalid-types"
            malformed_types["dependencies"][0]["source"]["project_id"] = 7
            malformed_types["dependencies"][0]["status"] = 1
            malformed_types["dependencies"][0]["evidence_refs"] = [1]
            self.assertTrue(validate_snapshot(malformed_types))
            self.assertEqual(portfolio.ingest_snapshot(malformed_types, self.context)["status"], "failure")

            legacy_rule = json.loads(json.dumps(snapshot))
            legacy_rule["snapshot_id"] = "snapshot.legacy-sot.1"
            legacy_rule["source_of_truth"][0].pop("source_rule_id", None)
            legacy_rule["source_of_truth"][0]["domain"] = "legacy.checkout.api"
            self.assertEqual(portfolio.ingest_snapshot(legacy_rule, self.context)["status"], "success")
            legacy_update = json.loads(json.dumps(legacy_rule))
            legacy_update["snapshot_id"] = "snapshot.legacy-sot.2"
            legacy_update["source_of_truth"][0]["status"] = "conflict"
            legacy_update["source_of_truth"][0]["evidence"].append("legacy/updated.json")
            self.assertEqual(portfolio.ingest_snapshot(legacy_update, self.context)["status"], "success")
            legacy_rules = portfolio.source_of_truth(domain="legacy.checkout.api")
            self.assertEqual(len(legacy_rules), 1)
            self.assertEqual(legacy_rules[0]["status"], "conflict")
            self.assertIn("legacy/updated.json", legacy_rules[0]["evidence_refs"])

            evidence_gap = json.loads(json.dumps(legacy_update))
            evidence_gap["snapshot_id"] = "snapshot.legacy-sot.3"
            evidence_gap["dependencies"][0].pop("evidence", None)
            evidence_gap["dependencies"][0]["evidence_refs"] = []
            evidence_gap["dependencies"][0]["status"] = "active"
            self.assertEqual(portfolio.ingest_snapshot(evidence_gap, self.context)["status"], "success")
            retained_edge = portfolio.relationships(relationship_type="runtime_api", status="active")
            retained_cross_root = next(edge for edge in retained_edge if edge["dependency_id"] == "dep.polyrepo.cross-root")
            self.assertIn("content-tool/.aine/registry.json", retained_cross_root["evidence_refs"])

            route_reference = json.loads(json.dumps(snapshot))
            route_reference["snapshot_id"] = "snapshot.api-route"
            route_reference["artifacts"][0]["route"] = "/api/v1/checkout"
            self.assertEqual(portfolio.ingest_snapshot(route_reference, self.context)["status"], "success")
            route_leak = json.loads(json.dumps(snapshot))
            route_leak["snapshot_id"] = "snapshot.api-route-leak"
            route_leak["artifacts"][0]["route"] = "/Users/w/checkout"
            leaked_route = portfolio.ingest_snapshot(route_leak, self.context)
            self.assertEqual(leaked_route["status"], "failure")
            self.assertEqual(leaked_route["error_code"], "invalid_snapshot")

            for index, leaked_path in enumerate((r"\Users\private\api.yaml", r"C:Users\private\api.yaml", "~otheruser/api.yaml", "  /Users/private/api.yaml")):
                bypass = json.loads(json.dumps(snapshot))
                bypass["snapshot_id"] = f"snapshot.path-bypass-{index}"
                bypass["artifacts"][0]["path"] = leaked_path
                self.assertEqual(portfolio.ingest_snapshot(bypass, self.context)["status"], "failure")

            with tempfile.TemporaryDirectory() as tie_directory:
                tie_store = LocalRecordStore(
                    Path(tie_directory) / "control-plane.sqlite",
                    clock=lambda: "2026-01-03T00:00:00+00:00",
                )
                tie_portfolio = PortfolioRegistry(tie_store)
                first = json.loads(json.dumps(snapshot))
                first["snapshot_id"] = "snapshot.tie.2"
                first["dependencies"][0]["status"] = "old"
                second = json.loads(json.dumps(snapshot))
                second["snapshot_id"] = "snapshot.tie.1"
                second["dependencies"][0]["status"] = "new"
                self.assertEqual(tie_portfolio.ingest_snapshot(first, self.context)["status"], "success")
                self.assertEqual(tie_portfolio.ingest_snapshot(second, self.context)["status"], "success")
                tied_edge = next(edge for edge in tie_portfolio.relationships() if edge["dependency_id"] == "dep.polyrepo.cross-root")
                self.assertEqual(tied_edge["status"], "new")
                self.assertEqual(tied_edge["observed_snapshot_id"], "snapshot.tie.1")

    def test_self_hosted_http_transport_exposes_read_only_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalRecordStore(Path(directory) / "control-plane.sqlite")
            service = ControlPlaneService(
                store,
                authorization_rules=[
                    {"rule_id": "rule.read-portfolio", "effect": "allow", "action": "read", "resource": "portfolio/*", "roles": ["developer"]}
                ],
            )
            server = ControlPlaneHTTPServer(("127.0.0.1", 0), service)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                with urlopen(f"{base}/healthz") as response:
                    health = json.loads(response.read())
                self.assertEqual(health["status"], "ok")

                snapshot = json.loads((FIXTURE_DIR / "registry_snapshot.json").read_text(encoding="utf-8"))
                request = Request(
                    f"{base}/v1/snapshots",
                    data=json.dumps(snapshot).encode("utf-8"),
                    headers={"Content-Type": "application/json", "X-AINE-Actor": "agent.codex"},
                    method="POST",
                )
                with urlopen(request) as response:
                    ingested = json.loads(response.read())
                self.assertEqual(ingested["status"], "success")

                with urlopen(f"{base}/v1/relationships?project_id=reference.consumer") as response:
                    relationship_view = json.loads(response.read())
                self.assertEqual(relationship_view["schema"], "aine.control-plane.relationships-view.v1")
                self.assertTrue(relationship_view["read_only"])
                self.assertEqual([edge["dependency_id"] for edge in relationship_view["relationships"]], ["dependency.reference.1"])
                self.assertEqual(relationship_view["relationships"][0]["observed_snapshot_id"], "snapshot.reference.1")
                self.assertEqual(relationship_view["provenance"]["snapshot_count"], 1)

                with urlopen(f"{base}/v1/source-of-truth?domain=reference.api") as response:
                    source_view = json.loads(response.read())
                self.assertEqual(source_view["schema"], "aine.control-plane.source-of-truth-view.v1")
                self.assertTrue(source_view["read_only"])
                self.assertEqual(source_view["source_of_truth"][0]["authority"]["project_id"], "reference.provider")
                self.assertEqual(source_view["source_of_truth"][0]["observed_snapshot_id"], "snapshot.reference.1")

                with urlopen(f"{base}/v1/projects/reference.provider/impact") as response:
                    impact_view = json.loads(response.read())
                self.assertEqual(len(impact_view["source_of_truth"]), 1)

                policy_request = {
                    "policy": {"policy_id": "policy.http", "mode": "enforced", "required_checks": ["tests"]},
                    "checks": [{"check_id": "tests", "status": "fail"}],
                }
                policy_request = Request(
                    f"{base}/v1/policies/evaluate",
                    data=json.dumps(policy_request).encode("utf-8"),
                    headers={"Content-Type": "application/json", "X-AINE-Actor": "agent.codex"},
                    method="POST",
                )
                with self.assertRaises(HTTPError) as raised:
                    urlopen(policy_request)
                self.assertEqual(raised.exception.code, 409)
                decision = json.loads(raised.exception.read())
                self.assertTrue(decision["blocked"])

                authorization_request = Request(
                    f"{base}/v1/authorization/evaluate",
                    data=json.dumps({
                        "subject": {"subject_id": "agent.codex", "roles": ["developer"]},
                        "action": "read",
                        "resource": "portfolio/reference",
                    }).encode("utf-8"),
                    headers={"Content-Type": "application/json", "X-AINE-Actor": "agent.codex"},
                    method="POST",
                )
                with urlopen(authorization_request) as response:
                    authorization = json.loads(response.read())
                self.assertEqual(authorization["status"], "allow")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()


class CorsOptInTest(unittest.TestCase):
    def _spawn(self, **kwargs):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = LocalRecordStore(Path(directory.name) / "control-plane.sqlite")
        server = ControlPlaneHTTPServer(("127.0.0.1", 0), ControlPlaneService(store), **kwargs)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def test_cors_stays_off_by_default(self):
        base = self._spawn()
        with urlopen(f"{base}/v1/projects") as response:
            self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))
        with self.assertRaises(HTTPError) as raised:
            urlopen(Request(f"{base}/v1/projects", method="OPTIONS"))
        self.assertEqual(raised.exception.code, 501)

    def test_cors_opt_in_names_exactly_one_origin(self):
        base = self._spawn(cors_origin="http://localhost:4173")
        with urlopen(f"{base}/v1/projects") as response:
            self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), "http://localhost:4173")
            self.assertEqual(response.headers.get("Vary"), "Origin")
        preflight = Request(
            f"{base}/v1/projects",
            method="OPTIONS",
            headers={
                "Origin": "http://localhost:4173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type, x-aine-actor",
            },
        )
        with urlopen(preflight) as response:
            self.assertEqual(response.status, 204)
            self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), "http://localhost:4173")
            self.assertEqual(response.headers.get("Access-Control-Allow-Methods"), "GET, POST, OPTIONS")
            self.assertEqual(response.headers.get("Access-Control-Allow-Headers"), "Content-Type, X-AINE-Actor")


class RetirementProjectionTests(unittest.TestCase):
    """Records absent from the latest snapshot are retired, never deleted."""

    def setUp(self):
        self.context = AdapterContext(
            "retirement-v1",
            actor={"id": "agent.codex", "roles": ["approver"], "teams": ["platform"], "source": "token"},
        )
        self.first = json.loads((FIXTURE_DIR / "registry_snapshot.json").read_text(encoding="utf-8"))
        self.first["snapshot_id"] = "snapshot.S1"
        self.second = json.loads(json.dumps(self.first))
        self.second["snapshot_id"] = "snapshot.S2"
        self.second["dependencies"] = []
        self.second["artifacts"] = []
        self.second["projects"] = [project for project in self.second["projects"] if project["project_id"] == "reference.provider"]

    def _registry(self, *snapshots, clock=None):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        kwargs = {"clock": clock} if clock else {}
        store = LocalRecordStore(Path(directory.name) / "control-plane.sqlite", **kwargs)
        registry = PortfolioRegistry(store)
        for snapshot in snapshots:
            self.assertEqual(registry.ingest_snapshot(snapshot, self.context)["status"], "success")
        return store, registry

    def test_projects_and_artifacts_carry_presence_and_observation_provenance(self):
        _, registry = self._registry(self.first, self.second)
        self.assertEqual(registry.latest_snapshot_id(), "snapshot.S2")
        projects = {project["project_id"]: project for project in registry.projects(include_retired=True)}
        provider = projects["reference.provider"]
        self.assertEqual(provider["observed_snapshot_id"], "snapshot.S2")
        self.assertEqual(provider["observed_snapshot_ids"], ["snapshot.S1", "snapshot.S2"])
        self.assertTrue(provider["present_in_latest"])
        consumer = projects["reference.consumer"]
        self.assertEqual(consumer["observed_snapshot_ids"], ["snapshot.S1"])
        self.assertFalse(consumer["present_in_latest"])
        self.assertEqual([project["project_id"] for project in registry.projects()], ["reference.provider"])
        self.assertEqual(registry.artifacts(), [])
        artifacts = registry.artifacts(include_retired=True)
        self.assertTrue(artifacts)
        self.assertTrue(all(artifact["present_in_latest"] is False for artifact in artifacts))
        self.assertTrue(all(artifact["observed_snapshot_ids"] == ["snapshot.S1"] for artifact in artifacts))

    def test_provenance_is_absent_when_nothing_was_ingested(self):
        _, registry = self._registry()
        self.assertIsNone(registry.latest_snapshot_id())
        self.assertEqual(registry.projects(), [])
        self.assertEqual(ControlPlaneService(registry.store).portfolio_provenance()["latest_snapshot_id"], None)

    def test_relationships_view_provenance_declares_latest_snapshot(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = LocalRecordStore(Path(directory.name) / "control-plane.sqlite")
        server = ControlPlaneHTTPServer(("127.0.0.1", 0), ControlPlaneService(store))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        for snapshot in (self.first, self.second):
            request = Request(
                f"{base}/v1/snapshots",
                data=json.dumps(snapshot).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-AINE-Actor": "agent.codex"},
                method="POST",
            )
            with urlopen(request) as response:
                self.assertEqual(json.loads(response.read())["status"], "success")
        with urlopen(f"{base}/v1/relationships") as response:
            view = json.loads(response.read())
        self.assertEqual(view["provenance"]["snapshot_ids"], ["snapshot.S1", "snapshot.S2"])
        self.assertEqual(view["provenance"]["snapshot_count"], 2)
        self.assertEqual(view["provenance"]["latest_snapshot_id"], "snapshot.S2")
        schema = json.loads((Path(__file__).parents[1] / "aine_control_plane" / "schema" / "relationships-view.v1.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(set(view["provenance"]), set(schema["properties"]["provenance"]["properties"]))

    def test_edges_absent_from_the_latest_snapshot_are_retired_by_default(self):
        store, registry = self._registry(self.first, self.second)
        self.assertEqual(registry.relationships(), [])
        self.assertEqual(registry.dependencies(), [])
        self.assertEqual(registry.relationships(project_id="reference.consumer"), [])
        # Nothing was deleted: both snapshots are still stored, and the edge is still queryable.
        self.assertEqual(registry.snapshot_ids(), ["snapshot.S1", "snapshot.S2"])
        self.assertEqual(len(store.list_records("snapshot")), 2)

    def test_retired_edges_remain_queryable_and_are_never_deleted(self):
        _, registry = self._registry(self.first, self.second)
        retired = registry.relationships(include_retired=True)
        self.assertEqual([edge["dependency_id"] for edge in retired], ["dependency.reference.1"])
        self.assertIs(retired[0]["present_in_latest"], False)
        self.assertEqual(retired[0]["observed_snapshot_id"], "snapshot.S1")
        self.assertEqual(retired[0]["observed_snapshot_ids"], ["snapshot.S1"])
        # A re-declaration in a later snapshot un-retires the edge and keeps its history.
        third = json.loads(json.dumps(self.first))
        third["snapshot_id"] = "snapshot.S3"
        self.assertEqual(registry.ingest_snapshot(third, self.context)["status"], "success")
        current = registry.relationships()
        self.assertEqual([edge["dependency_id"] for edge in current], ["dependency.reference.1"])
        self.assertIs(current[0]["present_in_latest"], True)
        self.assertEqual(current[0]["observed_snapshot_ids"], ["snapshot.S1", "snapshot.S3"])

    def test_impact_excludes_retired_edges(self):
        _, registry = self._registry(self.first, self.second)
        report = registry.impact("reference.provider")
        self.assertEqual(report["relationships"], [])
        self.assertEqual(report["affected_projects"], [])
        self.assertEqual(report["latest_snapshot_id"], "snapshot.S2")
        # The retired consumer id still resolves for anything that references it.
        self.assertEqual(registry.get_project("reference.consumer")["project_id"], "reference.consumer")
        single_registry = self._registry(self.first)[1]
        live = single_registry.impact("reference.provider")
        self.assertEqual([edge["dependency_id"] for edge in live["relationships"]], ["dependency.reference.1"])
        self.assertEqual(live["latest_snapshot_id"], "snapshot.S1")

    def test_retirement_uses_insertion_order_when_snapshot_clocks_tie(self):
        _, registry = self._registry(self.first, self.second, clock=lambda: "2026-01-03T00:00:00+00:00")
        self.assertEqual(registry.latest_snapshot_id(), "snapshot.S2")
        self.assertEqual(registry.relationships(), [])
        _, reversed_registry = self._registry(self.second, self.first, clock=lambda: "2026-01-03T00:00:00+00:00")
        self.assertEqual(reversed_registry.latest_snapshot_id(), "snapshot.S1")
        self.assertEqual([edge["dependency_id"] for edge in reversed_registry.relationships()], ["dependency.reference.1"])

    def test_http_views_expose_include_retired_as_an_explicit_opt_in(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = LocalRecordStore(Path(directory.name) / "control-plane.sqlite")
        server = ControlPlaneHTTPServer(("127.0.0.1", 0), ControlPlaneService(store))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        for snapshot in (self.first, self.second):
            request = Request(
                f"{base}/v1/snapshots",
                data=json.dumps(snapshot).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-AINE-Actor": "agent.codex"},
                method="POST",
            )
            with urlopen(request) as response:
                self.assertEqual(json.loads(response.read())["status"], "success")
        with urlopen(f"{base}/v1/relationships") as response:
            self.assertEqual(json.loads(response.read())["relationships"], [])
        with urlopen(f"{base}/v1/relationships?include_retired=true") as response:
            view = json.loads(response.read())
        self.assertEqual([edge["dependency_id"] for edge in view["relationships"]], ["dependency.reference.1"])
        self.assertIs(view["relationships"][0]["present_in_latest"], False)
        with urlopen(f"{base}/v1/projects") as response:
            self.assertEqual([p["project_id"] for p in json.loads(response.read())["projects"]], ["reference.provider"])
        with urlopen(f"{base}/v1/projects?include_retired=true") as response:
            self.assertEqual(
                [p["project_id"] for p in json.loads(response.read())["projects"]],
                ["reference.consumer", "reference.provider"],
            )
        with urlopen(f"{base}/v1/projects/reference.provider/impact") as response:
            report = json.loads(response.read())
        self.assertEqual(report["relationships"], [])
        self.assertEqual(report["latest_snapshot_id"], "snapshot.S2")
