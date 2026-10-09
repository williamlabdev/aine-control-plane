# AINE Control Plane UI

Local React + Tailwind dashboard for the self-hosted Control Plane.

The UI keeps scanned repositories read-only. It consumes the existing
loopback API, does not scan repositories, access SQLite directly, execute
agents, or invoke deployment tools. Its Proposal Mode can create
Control-Plane-owned append-only drafts for features, requirements, and project
registrations; it does not edit source files or Git state.

The Remediation view adds a bounded finding-to-validation workflow. It creates
an append-only remediation plan, submits it through the existing approval
workflow, and can request only a `dry_run` execution record. The UI never
accepts local paths and never runs an agent, shell command, Git operation, or
deployment. A separately authorized Local Runner may report its status and
portable validation evidence through the API.

The dashboard includes separate Governance, Security, and Evals views. They
read policy, RBAC/ABAC, approval, audit, adapter, contract, and evidence
signals from the existing API. They do not infer a compliance score: missing,
unresolved, contradictory, and not-configured states remain visible as
`UNKNOWN`, `CONFLICT`, or `NOT CONFIGURED`.

The Projects view is the read-only Portfolio surface. It consumes
`/v1/relationships`, `/v1/source-of-truth`, and project impact responses to show
workspace-root selection, cross-root edges, authority declarations, portable
evidence references, and snapshot provenance. It does not rescan repositories
or infer missing relationships/authority.

## Local development

From the `ui` directory:

```bash
npm ci --include=optional --ignore-scripts
npm run dev
```

Use `npm ls --all` to verify the installed tree. Do not use
`npm ls --package-lock-only` as a local-platform completeness check: the lock
file includes optional packages for other CPUs, including the `wasm32` Tailwind
fallback, which npm correctly skips on macOS arm64. The platform-native
Tailwind package remains installed and the UI build does not require the
WASI-only subtree.

Start the Control Plane separately on `127.0.0.1:8787` (from the repository
root: `PYTHONPATH=. python3 examples/run_server.py --db ./control-plane.sqlite`).
Vite proxies `/healthz` and `/v1` to that service — leave `VITE_API_BASE_URL`
unset for local development. Set `AINE_API_TARGET` when the API runs on
another local address.

A fresh database renders every view empty. Seed it with the bundled example
snapshot so the Projects/Relationships/Source-of-truth views have data
(run this from the repository root, not from `ui/` — the fixture path is
relative to the root; re-running it is safe and reports `duplicate: true`):

```bash
curl -X POST http://127.0.0.1:8787/v1/snapshots \
  -H "Content-Type: application/json" -H "X-AINE-Actor: developer" \
  --data @aine_control_plane/fixtures/registry_snapshot.json
```

The production build can target a separately hosted Control Plane with:

```bash
VITE_API_BASE_URL=https://control-plane.example.test npm run build
```

A build served from a different origin than the API is cross-origin, and the
reference server rejects cross-origin browser requests by default. Opt in by
starting it with `--cors-origin` set to the UI's exact origin (or pass
`cors_origin=` to `serve()`); this names one origin and is not a substitute
for a real authentication and TLS boundary.

The frontend does not provide authentication. A non-loopback deployment must
place it behind the Control Plane's authentication and authorization boundary.
For local trusted proposal writes, set `VITE_AINE_ACTOR` before `npm run dev`.
The resulting `X-AINE-Actor` header is trusted context only and is not
authentication, so approval decisions from it are refused
(`approval_identity_unverified`) until a consumer verifies identity. Without it, the proposal form stays disabled while read-only
views remain available.
The Security view is an inventory of declared boundaries and observed
evidence, not a replacement for TLS, identity, secret management, or a
provider-specific security scanner.

### Dependency security checks

The UI keeps `package-lock.json` as its canonical lockfile. Run the npm-only
check from this directory with:

```bash
npm run security:audit
```

The audit is read-only. Do not run `npm audit fix` as part of a security gate;
dependency updates require a separately reviewed change and lockfile update.
