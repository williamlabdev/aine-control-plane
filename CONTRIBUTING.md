# Contributing

Contributions should preserve the public boundary described in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

Before opening a change:

1. keep the implementation dependency-free unless the public boundary is explicitly revised;
2. add or update a JSON Schema and fixture for every new portable field or relationship;
3. add a regression or conformance test for every new behavior;
4. verify that tests, examples, and documentation contain no secrets, customer data, or machine-local paths;
5. run `python -m unittest discover -s tests -p 'test_*.py'` and `python -m compileall -q aine_control_plane tests`.

`tests/test_portfolio_chain_e2e.py` walks the whole correlated chain — a live
producer run becomes an observation, the observation joins a stored portfolio
snapshot, and the correlation identifier answers as a query. It needs two
neighbours that are deliberately not dependencies of this package, so it skips
unless both are present:

- `AINE_REGISTRY_PATH` — an AINE Registry checkout, driven through its CLI.
  Defaults to a sibling `aine-registry` directory. The same checkout, when
  present, is also compared byte-for-byte against the vendored
  `fixtures/registry.v1.schema.json` by `tests/test_registry_schema_contract.py`
  (see the `.SOURCE` note beside it for how to refresh the copy).
- `AINE_AIRT_LIVE_PATH` — a directory of airt run directories, each holding an
  `events.db` with the `airt.pub` beside it. Live local output, never a
  fixture, so there is no default.

Provider-specific integrations should be implemented in a separate adapter
repository rather than added to this core.
