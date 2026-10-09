from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from aine_control_plane.approval import ApprovalWorkflow
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


if __name__ == "__main__":
    unittest.main()
