from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aine_control_plane.approval import ApprovalWorkflow
from aine_control_plane.change_requests import validate_change_request
from aine_control_plane.contracts import AdapterContext, attribute_actor
from aine_control_plane.service import ControlPlaneService
from aine_control_plane.store import LocalRecordStore


CALLER = AdapterContext("attribution-test", actor={"id": "agent.caller", "roles": ["approver"]})
NO_ACTOR = AdapterContext("attribution-test")


class AttributeActorTests(unittest.TestCase):
    def test_payload_cannot_name_the_actor(self):
        self.assertEqual(
            attribute_actor({"requested_by": "someone.else"}, CALLER, "requested_by"),
            {"requested_by": "agent.caller", "authenticated_actor": "agent.caller", "claimed_actor": "someone.else"},
        )

    def test_missing_context_names_nobody_and_keeps_the_claim(self):
        self.assertEqual(
            attribute_actor({"requested_by": "someone.else"}, NO_ACTOR, "requested_by"),
            {"requested_by": "unknown", "authenticated_actor": None, "claimed_actor": "someone.else"},
        )

    def test_subject_id_counts_as_authenticated(self):
        context = AdapterContext("attribution-test", actor={"subject_id": "user.42"})
        self.assertEqual(attribute_actor({}, context, "reported_by")["reported_by"], "user.42")


class ApprovalAttributionTests(unittest.TestCase):
    def _create(self, context: AdapterContext):
        with tempfile.TemporaryDirectory() as directory:
            workflow = ApprovalWorkflow(LocalRecordStore(Path(directory) / "control-plane.sqlite"))
            created = workflow.create(
                {
                    "approval_id": "approval.spoof.1",
                    "subject": {"change_id": "change.1"},
                    "scope": {"project_id": "reference.consumer"},
                    "requested_by": "someone.else",
                },
                context,
            )
            self.assertEqual(created["status"], "success")
            return created["result"]["approval"]

    def test_spoofed_requested_by_records_the_caller(self):
        approval = self._create(CALLER)
        self.assertEqual(approval["requested_by"], "agent.caller")
        self.assertEqual(approval["claimed_actor"], "someone.else")

    def test_spoofed_requested_by_without_context_records_nobody(self):
        approval = self._create(NO_ACTOR)
        self.assertEqual(approval["requested_by"], "unknown")
        self.assertIsNone(approval["authenticated_actor"])
        self.assertEqual(approval["claimed_actor"], "someone.else")


class ChangeRequestAttributionTests(unittest.TestCase):
    def test_spoofed_requested_by_records_the_caller_and_stays_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            service = ControlPlaneService(LocalRecordStore(Path(directory) / "control-plane.sqlite"))
            result = service.create_change_request(
                {
                    "change_id": "change.spoof.1",
                    "title": "Spoofed requester",
                    "description": "The payload names someone other than the caller.",
                    "scope": {"project_ids": ["aine-control-plane"]},
                    "requested_by": "someone.else",
                },
                CALLER,
            )
            self.assertEqual(result["status"], "success")
            record = result["result"]["change_request"]
            self.assertEqual(record["requested_by"], "agent.caller")
            self.assertEqual(record["claimed_actor"], "someone.else")
            self.assertEqual(validate_change_request(record), [])


if __name__ == "__main__":
    unittest.main()
