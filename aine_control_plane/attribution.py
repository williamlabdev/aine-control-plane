from __future__ import annotations

from typing import Any, Iterable, Mapping


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
