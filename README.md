# AINE Control Plane Core

Provider-neutral, dependency-free primitives for building read-only portfolio
governance around [`aine-registry`](https://github.com/williamlabdev/aine-registry).

This repository is the public core boundary. It defines portable contracts and
reference implementations; it is not a hosted control plane, an agent runner,
or a provider integration product.

## What is included

- read-only adapter contracts and machine-readable outcomes;
- portable adapter configuration and local-path/credential-field validation;
- append-only SQLite evidence and audit storage;
- portable Registry snapshot ingest, project/artifact/dependency/relationship/source-of-truth views, and impact analysis;
- advisory or opt-in enforced policy evaluation, including unknown and conflict states;
- deterministic RBAC/ABAC authorization evaluation;
- retention evaluation without deletion;
- approval, change-request, remediation-plan, and runner-session record workflows (read-only proposals; every decision is an explicit record);
- a reference self-hosted HTTP transport and a local React UI over the same read-only boundary;
- JSONL, SQLite, static-fixture, and airt chain-projection reference adapters;
- snapshot-backed `integration-observation.v1` records for report-only Orvena/airt evidence;
- JSON Schemas, fixtures, and conformance tests for the public boundary.

The stable wire identifiers remain under the `aine.control-plane.*.v1`
namespace. The Python package is intentionally dependency-free and can be
embedded by a service, CLI, CI integration, or another adapter implementation.

The report-only integration contract links a producer `run_id` to a shared
`correlation_id` and an already-ingested Registry `snapshot_id`. It carries
normalized claims, a digest of the native producer record, the identifier the
producing adapter gives that record's format, and optional portable evidence
references; it never embeds native payloads, credentials, or machine-local
paths. `success`, `failure`, `unknown`, and `conflict` remain distinct
observations, and `read_only` is always true.

## What is intentionally excluded

- hosted SaaS, tenant administration, billing, and commercial operations;
- HTTP authentication, session management, and hardened network exposure (the reference transport binds locally and is for local or demo use);
- provider SDKs, credentials, secret-manager resolution, and external identity integrations;
- source-repository mutation, Git operations, deployment execution, and agent execution;
- customer-specific business logic and private portfolio data.

Those concerns belong in an application or project adapter that consumes these
contracts. The core has no source-repository mutation APIs and does not make
network calls. File-backed adapters write to their configured destination, so
callers must keep that destination outside scanned source repositories.

## Install

The package has no runtime dependencies and supports Python 3.9 or newer. It
is not published to PyPI; install it from a tagged release:

```bash
pip install "aine-control-plane @ git+https://github.com/williamlabdev/aine-control-plane.git@v0.8.0"
```

For a checkout, install in editable mode so the tests and examples resolve
the package without `PYTHONPATH`:

```bash
git clone https://github.com/williamlabdev/aine-control-plane.git
cd aine-control-plane
pip install -e .
```

The wire contracts are versioned independently of the package
(`aine.control-plane.*.v1`); see the compatibility notes in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start

```python
from aine_control_plane.contracts import AdapterContext
from aine_control_plane.governance import evaluate_policy

context = AdapterContext("request-1", actor={"id": "developer"})
decision = evaluate_policy(
    {"policy_id": "release", "required_checks": ["tests"]},
    [{"check_id": "tests", "status": "pass"}],
    context,
)
assert decision["status"] == "pass"
```

To see the whole surface at once, run the reference server, seed it with the
bundled example snapshot, and start the UI:

```bash
# terminal 1 — the reference server
PYTHONPATH=. python3 examples/run_server.py --db ./control-plane.sqlite

# terminal 2 — seed one Registry snapshot so the views have data
curl -X POST http://127.0.0.1:8787/v1/snapshots \
  -H "Content-Type: application/json" -H "X-AINE-Actor: developer" \
  --data @aine_control_plane/fixtures/registry_snapshot.json

# terminal 2 — the UI (Vite proxies /v1 to the server; leave VITE_API_BASE_URL unset)
cd ui && npm ci --include=optional --ignore-scripts && npm run dev
```

The UI shows projects, relationships, source-of-truth rules, impact,
evidence, audit events, and the change-request/remediation/runner workflows.
For local development the Vite dev server proxies API calls, so no
cross-origin setup is needed. To serve a production UI build from a different
origin, start the server with `--cors-origin <ui-origin>` and build the UI
with `VITE_API_BASE_URL` pointing at the server (see `ui/README.md`).

The reference adapters are intentionally explicit about their runtime
destination:

```python
from pathlib import Path

from aine_control_plane.adapters import JsonlEvidenceSinkAdapter

sink = JsonlEvidenceSinkAdapter(Path("evidence.jsonl"))
```

The destination path above is runtime configuration and is never part of a
portable adapter configuration or evidence record.

`AirtChainProjectionAdapter` turns an airt run the caller has already read into
a snapshot-joined observation. airt publishes no portable evidence export, so
the adapter supplies the format identifier it owns,
`aine.control-plane.airt-chain-projection.v1`, rather than naming a format airt
does not declare. It keeps only chain-level fields, lists what it dropped, and
asserts no chain verification it did not perform.

```python
from aine_control_plane.adapters import AirtChainProjectionAdapter

outcome = AirtChainProjectionAdapter().collect(
    {"run": run, "snapshot_id": snapshot_id},
    context,
)
observation = outcome["result"]
```

## Development

The project has no runtime dependencies.

```bash
python -m unittest discover -s tests -p 'test_*.py'
python -m compileall -q aine_control_plane tests
PYTHONPATH=. python examples/policy_evaluation.py
```

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the public boundary and
[SECURITY.md](SECURITY.md) before embedding the package in a service.

`PortfolioRegistry.relationships()` and `PortfolioRegistry.source_of_truth()`
query only records persisted from a portable Registry snapshot. They do not
rescan repositories or infer runtime semantics. Projections are "as of the
latest snapshot": a record the latest snapshot no longer declares is retired
(kept, but omitted) until you pass `include_retired=True` or
`?include_retired=true`. Topology-only Registry edges
with `kind` `portfolio`, `governance`, or `integration` remain queryable but do
not expand `PortfolioRegistry.impact()` unless the manifest explicitly sets
`impact: true`. Unresolved external providers remain on the edge evidence but
are not returned as project records in `affected_projects`.

## Further reading

The governance model these contracts implement, on the author's site:

- [Change-Intent Governance: The Missing Layer](https://williamlab.dev/articles/change-intent-governance) — impact computed from snapshots, decisions on an append-only ledger.
- [Accountable Generation: Intent as the Artifact of Record](https://williamlab.dev/articles/accountable-generation) — why intent, not code, is what gets versioned and audited.
- [Governance-Driven Engineering for AI-Native Teams](https://williamlab.dev/articles/governance-driven-engineering) — how autonomy, review, policy, and evaluation fit together.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Relicensed from MIT on 2026-08-27 by the sole copyright holder; copies
distributed before that date remain available under their original MIT terms.
