# Security policy

This repository contains a library and reference adapters. It is not an
internet-facing service and does not provide authentication, authorization
transport, secret storage, or deployment controls by itself.

## Reporting a vulnerability

Please do not open a public issue containing exploit details or credentials.
Use the repository's private security contact or GitHub security advisory
workflow when available. Remove secrets from all reports and include the
smallest reproducible case.

## Boundary assumptions

- portable configuration supports credential references and rejects known raw-credential fields; opaque option values require adapter-specific validation;
- validation rejects known secret-bearing fields and runtime-local paths;
- reference adapters make no network calls;
- the local store is append-only by record identity and reports conflicting writes;
- policy and authorization evaluation preserve `unknown` and `conflict` outcomes;
- consumers must provide the authenticated actor and network boundary before exposing a service.
  Records name the actor only from that context: `requested_by` / `reported_by`
  hold the authenticated actor or `unknown`, never a payload value. What the
  payload claimed is kept separately as `claimed_actor`; a row whose
  `authenticated_actor` is null marks a path that is not wired to identity yet.
  `actor_source` says where the context got the actor. The reference HTTP
  transport reads an unverified `X-AINE-Actor` header and records `header`: on
  those rows the caller wrote both `authenticated_actor` and `claimed_actor`,
  so their agreeing proves nothing, and because write routes reject a missing
  header, they are never null. Consumers that verify identity should set
  `source` on the context actor (for example `token`).
  `GET /v1/audit/actor-attribution` counts mismatched and null rows per UTC day
  and source; it reports `unknown` until the service is given an
  `attribution_owner` who reads it.
- callers must keep SQLite/JSONL evidence destinations outside scanned source repositories.

Do not treat a passing unit test or a valid Registry snapshot as proof that a
deployment is secure. Provider integrations and deployment environments need
their own threat model, dependency scanning, and operational controls.
