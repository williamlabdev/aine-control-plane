from __future__ import annotations

from typing import Any, Iterable, Mapping

from .approval import ApprovalWorkflow, _parse_time


ACTOR_ATTRIBUTION_REPORT_SCHEMA = "aine.control-plane.actor-attribution-report.v1"


def actor_attribution_report(
    rows: Iterable[Mapping[str, Any]],
    owner: str | None,
    day: str | None = None,
) -> Mapping[str, Any]:
    """Count, per UTC day and ``actor_source``, the rows nobody reads otherwise.

    A mismatch is a row whose ``authenticated_actor`` and ``claimed_actor`` are
    both present and differ. A null row has no ``authenticated_actor``. Rows
    from a self-reported source (``header``) cannot mismatch unless the caller
    contradicts itself, so they are counted separately rather than folded in.

    The counts are only findings if someone reads them: without a named
    ``owner`` the report is ``unknown`` rather than ``success``.
    """
    buckets: dict[tuple[str, str], dict[str, int]] = {}
    for row in rows:
        record = row.get("record") or {}
        if "authenticated_actor" not in record:
            continue
        row_day = str(row.get("created_at", ""))[:10]
        if day is not None and row_day != day:
            continue
        authenticated = record.get("authenticated_actor")
        claimed = record.get("claimed_actor")
        source = record.get("actor_source") or ("unrecorded" if authenticated else "none")
        counts = buckets.setdefault((row_day, str(source)), {"rows": 0, "mismatched": 0, "null_authenticated": 0})
        counts["rows"] += 1
        if authenticated is None:
            counts["null_authenticated"] += 1
        elif claimed is not None and claimed != authenticated:
            counts["mismatched"] += 1
    return {
        "schema": ACTOR_ATTRIBUTION_REPORT_SCHEMA,
        "status": "success" if owner else "unknown",
        "owner": owner,
        "reason": None if owner else "no owner named for actor attribution findings",
        "day": day,
        "days": [
            {"day": row_day, "actor_source": source, **counts}
            for (row_day, source), counts in sorted(buckets.items())
        ],
        "read_only": True,
    }


UNVERIFIED_DECISION_REPORT_SCHEMA = "aine.control-plane.unverified-decision-report.v1"


def unverified_decision_report(
    workflow: ApprovalWorkflow,
    cutoff: str,
    owner: str | None,
) -> Mapping[str, Any]:
    """List approvals whose status would change without decisions from before ``cutoff``.

    ``cutoff`` is when decisions started requiring a verified actor source
    (the merge of the fix that added that gate). ``decided_at`` comes from the
    server clock inside ``decide()``, not from the caller, so it separates the
    older decisions without a schema change. Nothing is removed: some of these
    are probably real approvals that just cannot be verified now, so the report
    is for someone to read before ``_status()`` is changed to skip them.
    """
    cutoff_time = _parse_time(cutoff)
    approvals = []
    for request in workflow.store.list_records("approval"):
        approval_id = str(request.get("approval_id", ""))
        current = workflow.get(approval_id)
        if current is None:
            continue
        decisions = current["decisions"]
        earlier = [record for record in decisions if _parse_time(str(record.get("decided_at"))) < cutoff_time]
        if not earlier:
            continue
        later = [record for record in decisions if record not in earlier]
        status_without = workflow._status(request, later)
        if status_without != current["status"]:
            approvals.append({
                "approval_id": approval_id,
                "status": current["status"],
                "status_without_earlier_decisions": status_without,
                "earlier_decision_ids": [record.get("decision_id") for record in earlier],
            })
    return {
        "schema": UNVERIFIED_DECISION_REPORT_SCHEMA,
        "status": "success" if owner else "unknown",
        "owner": owner,
        "reason": None if owner else "no owner named for unverified decision findings",
        "cutoff": cutoff,
        "approvals": approvals,
        "read_only": True,
    }
