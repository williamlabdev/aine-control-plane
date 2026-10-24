from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from aine_control_plane.approval import ApprovalWorkflow
from aine_control_plane.attribution import unverified_decision_report
from aine_control_plane.contracts import AdapterContext
from aine_control_plane.server import ControlPlaneHTTPServer
from aine_control_plane.service import ControlPlaneService
from aine_control_plane.store import LocalRecordStore


def _call(url: str, body: dict, headers: dict):
    request = Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urlopen(request) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


class HeaderTransportCannotApproveTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        store = LocalRecordStore(Path(self._directory.name) / "control-plane.sqlite")
        self.server = ControlPlaneHTTPServer(("127.0.0.1", 0), ControlPlaneService(store))
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

        def stop():
            self.server.shutdown()
            self.server.server_close()
            thread.join(timeout=2)

        self.addCleanup(stop)

    def _request(self, approval_id: str, required_approvals: int):
        status, _ = _call(
            f"{self.base}/v1/approvals",
            {"approval_id": approval_id, "required_approvals": required_approvals, "required_roles": ["approver"]},
            {"X-AINE-Actor": "agent.requester"},
        )
        self.assertEqual(status, 201)

    def _status(self, approval_id: str) -> str:
        with urlopen(f"{self.base}/v1/approvals/{approval_id}") as response:
            return json.loads(response.read())["status"]

    def test_caller_cannot_grant_itself_the_approver_role(self):
        self._request("approval.self-grant", 1)
        status, body = _call(
            f"{self.base}/v1/approvals/approval.self-grant/decision",
            {"decision": "approve", "reason": "trust me"},
            {"X-AINE-Actor": "agent.requester", "X-AINE-Roles": "approver"},
        )
        self.assertEqual(status, 422)
        self.assertEqual(body["error_code"], "approval_identity_unverified")
        self.assertEqual(self._status("approval.self-grant"), "pending")

    def test_one_caller_cannot_fill_a_quorum_with_invented_actor_ids(self):
        self._request("approval.quorum", 2)
        for name in ("alice", "bob"):
            _call(
                f"{self.base}/v1/approvals/approval.quorum/decision",
                {"decision": "approve", "reason": "sock puppet"},
                {"X-AINE-Actor": name, "X-AINE-Roles": "approver"},
            )
        self.assertEqual(self._status("approval.quorum"), "pending")

    def test_reject_is_refused_too(self):
        self._request("approval.reject", 1)
        status, body = _call(
            f"{self.base}/v1/approvals/approval.reject/decision",
            {"decision": "reject", "reason": "veto"},
            {"X-AINE-Actor": "agent.other", "X-AINE-Roles": "approver"},
        )
        self.assertEqual(body.get("error_code"), "approval_identity_unverified")
        self.assertEqual(self._status("approval.reject"), "pending")


    def test_request_filed_from_a_header_cannot_be_decided_even_by_a_verified_approver(self):
        self._request("approval.header-filed", 1)
        verified = AdapterContext("identity-test", actor={"id": "human.reviewer", "roles": ["approver"], "source": "token"})
        outcome = self.server.service.decide_approval("approval.header-filed", "approve", "looks fine", verified)
        self.assertEqual(outcome["error_code"], "approval_request_unverified")
        self.assertEqual(self._status("approval.header-filed"), "pending")


class WorkflowSourceTests(unittest.TestCase):
    def test_missing_or_header_source_is_refused_and_verified_source_still_works(self):
        with tempfile.TemporaryDirectory() as directory:
            workflow = ApprovalWorkflow(LocalRecordStore(Path(directory) / "control-plane.sqlite"))
            creator = AdapterContext("identity-test", actor={"id": "agent.requester", "source": "token"})
            workflow.create({"approval_id": "approval.src", "required_roles": ["approver"]}, creator)
            for actor in ({"id": "a", "roles": ["approver"]}, {"id": "a", "roles": ["approver"], "source": "header"}):
                outcome = workflow.decide("approval.src", "approve", "x", AdapterContext("identity-test", actor=actor))
                self.assertEqual(outcome["status"], "failure")
                self.assertEqual(outcome["error_code"], "approval_identity_unverified")
            self.assertEqual(workflow.get("approval.src")["decisions"], [])
            verified = AdapterContext("identity-test", actor={"id": "a", "roles": ["approver"], "source": "token"})
            self.assertEqual(workflow.decide("approval.src", "approve", "x", verified)["status"], "success")
            self.assertEqual(workflow.get("approval.src")["status"], "approved")

class RequesterSourceTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.workflow = ApprovalWorkflow(LocalRecordStore(Path(self._directory.name) / "control-plane.sqlite"))

    def _create(self, approval_id: str, actor: dict):
        self.workflow.create({"approval_id": approval_id, "required_roles": ["approver"]}, AdapterContext("identity-test", actor=actor))

    def _decide(self, approval_id: str, decision: str, actor_id: str):
        context = AdapterContext("identity-test", actor={"id": actor_id, "roles": ["approver"], "source": "token"})
        return self.workflow.decide(approval_id, decision, "x", context)

    def test_unverified_request_source_is_refused(self):
        for approval_id, actor in (
            ("approval.header", {"id": "agent.requester", "source": "header"}),
            ("approval.unspecified", {"id": "agent.requester"}),
            ("approval.anonymous", {}),
        ):
            self._create(approval_id, actor)
            outcome = self._decide(approval_id, "approve", "human.reviewer")
            self.assertEqual(outcome["error_code"], "approval_request_unverified", approval_id)
            self.assertEqual(self.workflow.get(approval_id)["decisions"], [])

    def test_requester_cannot_approve_but_can_reject_its_own_request(self):
        self._create("approval.self", {"id": "agent.requester", "source": "token"})
        outcome = self._decide("approval.self", "approve", "agent.requester")
        self.assertEqual(outcome["error_code"], "approval_self_decision")
        self.assertEqual(self.workflow.get("approval.self")["status"], "pending")
        self.assertEqual(self._decide("approval.self", "reject", "agent.requester")["status"], "success")
        self.assertEqual(self.workflow.get("approval.self")["status"], "rejected")

    def test_another_verified_approver_succeeds_and_the_decision_records_its_source(self):
        self._create("approval.other", {"id": "agent.requester", "source": "token"})
        self.assertEqual(self._decide("approval.other", "approve", "human.reviewer")["status"], "success")
        approval = self.workflow.get("approval.other")
        self.assertEqual(approval["status"], "approved")
        self.assertEqual(approval["decisions"][0]["actor_source"], "token")


class UnverifiedDecisionReportTests(unittest.TestCase):
    def test_lists_only_approvals_whose_status_depends_on_decisions_before_the_cutoff(self):
        with tempfile.TemporaryDirectory() as directory:
            now = ["2026-10-08T00:00:00+00:00"]
            workflow = ApprovalWorkflow(LocalRecordStore(Path(directory) / "control-plane.sqlite"), clock=lambda: now[0])
            requester = AdapterContext("identity-test", actor={"id": "agent.requester", "source": "token"})
            approver = AdapterContext("identity-test", actor={"id": "human.reviewer", "roles": ["approver"], "source": "token"})
            for approval_id, decided_at in (("approval.before", "2026-10-08T00:00:00+00:00"), ("approval.after", "2026-10-10T00:00:00+00:00")):
                now[0] = decided_at
                workflow.create({"approval_id": approval_id, "required_roles": ["approver"], "requested_at": "2026-10-01T00:00:00+00:00"}, requester)
                workflow.decide(approval_id, "approve", "x", approver)

            report = unverified_decision_report(workflow, "2026-10-09T08:04:03+00:00", owner=None)
            self.assertEqual(report["status"], "unknown")
            self.assertEqual([row["approval_id"] for row in report["approvals"]], ["approval.before"])
            self.assertEqual(report["approvals"][0]["status_without_earlier_decisions"], "pending")
            self.assertEqual(workflow.get("approval.before")["status"], "approved")


if __name__ == "__main__":
    unittest.main()
