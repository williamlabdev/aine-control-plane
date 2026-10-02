from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import Request, urlopen

from aine_control_plane.approval import ApprovalWorkflow
from aine_control_plane.attribution import actor_attribution_report
from aine_control_plane.change_requests import validate_change_request
from aine_control_plane.contracts import AdapterContext, attribute_actor
from aine_control_plane.server import ControlPlaneHTTPServer
from aine_control_plane.service import ControlPlaneService
from aine_control_plane.store import LocalRecordStore


CALLER = AdapterContext("attribution-test", actor={"id": "agent.caller", "roles": ["approver"]})
NO_ACTOR = AdapterContext("attribution-test")


class AttributeActorTests(unittest.TestCase):
    def test_payload_cannot_name_the_actor(self):
        self.assertEqual(
            attribute_actor({"requested_by": "someone.else"}, CALLER, "requested_by"),
            {
                "requested_by": "agent.caller",
                "authenticated_actor": "agent.caller",
                "claimed_actor": "someone.else",
                "actor_source": "unspecified",
            },
        )

    def test_missing_context_names_nobody_and_keeps_the_claim(self):
        self.assertEqual(
            attribute_actor({"requested_by": "someone.else"}, NO_ACTOR, "requested_by"),
            {"requested_by": "unknown", "authenticated_actor": None, "claimed_actor": "someone.else", "actor_source": None},
        )

    def test_subject_id_counts_as_authenticated(self):
        context = AdapterContext("attribution-test", actor={"subject_id": "user.42"})
        self.assertEqual(attribute_actor({}, context, "reported_by")["reported_by"], "user.42")

    def test_context_source_is_recorded(self):
        context = AdapterContext("attribution-test", actor={"id": "agent.caller", "source": "token"})
        self.assertEqual(attribute_actor({}, context, "requested_by")["actor_source"], "token")


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


def _row(day: str, **record):
    return {"created_at": f"{day}T08:00:00+00:00", "record": record}


class ActorAttributionReportTests(unittest.TestCase):
    ROWS = [
        _row("2026-10-01", authenticated_actor="a", claimed_actor="a", actor_source="header"),
        _row("2026-10-01", authenticated_actor="a", claimed_actor="b", actor_source="header"),
        _row("2026-10-01", authenticated_actor="a", claimed_actor=None, actor_source="token"),
        _row("2026-10-01", authenticated_actor=None, claimed_actor="b", actor_source=None),
        _row("2026-10-01", authenticated_actor="a", claimed_actor="b"),
        _row("2026-10-02", authenticated_actor="a", claimed_actor="b", actor_source="header"),
        _row("2026-10-01", evidence_id="not.an.actor.record"),
    ]

    def test_counts_by_day_and_source(self):
        report = actor_attribution_report(self.ROWS, owner="team.security", day="2026-10-01")
        self.assertEqual(report["status"], "success")
        self.assertEqual(
            report["days"],
            [
                {"day": "2026-10-01", "actor_source": "header", "rows": 2, "mismatched": 1, "null_authenticated": 0},
                {"day": "2026-10-01", "actor_source": "none", "rows": 1, "mismatched": 0, "null_authenticated": 1},
                {"day": "2026-10-01", "actor_source": "token", "rows": 1, "mismatched": 0, "null_authenticated": 0},
                {"day": "2026-10-01", "actor_source": "unrecorded", "rows": 1, "mismatched": 1, "null_authenticated": 0},
            ],
        )

    def test_without_owner_the_report_is_unknown(self):
        report = actor_attribution_report(self.ROWS, owner=None)
        self.assertEqual(report["status"], "unknown")
        self.assertIsNone(report["owner"])
        self.assertEqual(len(report["days"]), 5)


class HttpActorSourceTests(unittest.TestCase):
    def test_header_actor_is_recorded_as_header_and_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalRecordStore(Path(directory) / "control-plane.sqlite")
            service = ControlPlaneService(store, attribution_owner="team.security")
            server = ControlPlaneHTTPServer(("127.0.0.1", 0), service)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                create = Request(
                    f"{base}/v1/approvals",
                    data=json.dumps(
                        {
                            "approval_id": "approval.header.1",
                            "subject": {"change_id": "change.1"},
                            "scope": {"project_id": "reference.consumer"},
                            "requested_by": "agent.caller",
                        }
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json", "X-AINE-Actor": "agent.caller"},
                    method="POST",
                )
                with urlopen(create) as response:
                    approval = json.loads(response.read())["result"]["approval"]
                self.assertEqual(approval["actor_source"], "header")
                # Header and payload agree because the caller wrote both.
                self.assertEqual(approval["authenticated_actor"], approval["claimed_actor"])

                with urlopen(f"{base}/v1/audit/actor-attribution") as response:
                    report = json.loads(response.read())
                self.assertEqual(report["status"], "success")
                self.assertEqual(report["owner"], "team.security")
                self.assertEqual(
                    [(entry["actor_source"], entry["rows"], entry["mismatched"]) for entry in report["days"]],
                    [("header", 1, 0)],
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
