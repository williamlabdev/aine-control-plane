"""Contract between aine-registry's snapshot schema and this repo's consumer.

aine-registry owns ``registry.v1.schema.json``. This repo reads snapshots with a
hand-written, deliberately lenient validator (``portfolio.validate_snapshot``)
so the public core stays dependency-free. Two kinds of drift matter:

* identifier drift: the ``schema`` constant diverges;
* requirement drift: this repo starts requiring a field the registry does not
  guarantee, so a valid registry snapshot would be rejected here.

The vendored copy under ``fixtures/`` is compared byte-for-byte against a real
registry checkout when one is available (``AINE_REGISTRY_PATH`` or a sibling
``aine-registry`` directory); otherwise that check is skipped, not passed.
"""

from __future__ import annotations

import copy
import json
import os
import unittest
from pathlib import Path

from aine_control_plane.portfolio import REGISTRY_SNAPSHOT_SCHEMA, validate_snapshot

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "aine_control_plane" / "fixtures"
VENDORED_SCHEMA = FIXTURE_DIR / "registry.v1.schema.json"
SNAPSHOT_FIXTURES = ("registry_snapshot.json", "registry_semantics_snapshot.json")
ITEM_DEFS = {"projects": "project", "artifacts": "artifact", "dependencies": "dependency"}


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


SCHEMA_RELATIVE = Path("registry") / "schema" / "registry.v1.schema.json"

# Fields this consumer requires that the registry schema does not (yet) declare.
# Each entry must name the upstream change that retires it; the sync test fails
# once the vendored copy declares the field, so the entry cannot be forgotten.
KNOWN_STRICTER_THAN_REGISTRY: set[tuple[str, str]] = set()


def _registry_checkout() -> Path | None:
    """Explicit AINE_REGISTRY_PATH wins and must be valid; else sibling; else None."""
    configured = os.environ.get("AINE_REGISTRY_PATH")
    if configured:
        path = Path(configured).expanduser()
        if not (path / SCHEMA_RELATIVE).is_file():
            raise AssertionError(f"AINE_REGISTRY_PATH={configured} has no {SCHEMA_RELATIVE}")
        return path
    sibling = Path(__file__).resolve().parents[2] / "aine-registry"
    return sibling if (sibling / SCHEMA_RELATIVE).is_file() else None


class RegistrySchemaContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = _load(VENDORED_SCHEMA)

    def test_schema_identifier_matches_registry(self) -> None:
        self.assertEqual(self.schema["properties"]["schema"].get("const"), REGISTRY_SNAPSHOT_SCHEMA)

    def test_fixtures_carry_every_top_level_field_registry_requires(self) -> None:
        for name in SNAPSHOT_FIXTURES:
            with self.subTest(fixture=name):
                snapshot = _load(FIXTURE_DIR / name)
                missing = [field for field in self.schema["required"] if field not in snapshot]
                self.assertEqual(missing, [], f"{name} lacks registry-required fields {missing}")
                self.assertEqual(validate_snapshot(snapshot), [])

    def test_consumer_never_requires_more_than_registry_guarantees(self) -> None:
        """Every field whose removal this repo rejects must be registry-required.

        The consumer may be looser than the registry (it only checks what it
        uses); it must never be stricter, or valid registry output breaks here.

        Only fields present in the fixture can be popped, so a new consumer
        rule on a field the fixture lacks is not caught here; it is caught by
        ``test_fixtures_carry_every_top_level_field_registry_requires``, whose
        baseline ``validate_snapshot(fixture) == []`` fails instead. Keep both.
        """
        snapshot = _load(FIXTURE_DIR / "registry_snapshot.json")
        registry_top = set(self.schema["required"])
        for field in list(snapshot):
            trimmed = copy.deepcopy(snapshot)
            trimmed.pop(field)
            if validate_snapshot(trimmed):
                with self.subTest(level="top", field=field):
                    self.assertIn(field, registry_top)
        for collection, definition in ITEM_DEFS.items():
            registry_item = set(self.schema["$defs"][definition].get("required", []))
            first = snapshot[collection][0]
            for field in list(first):
                trimmed = copy.deepcopy(snapshot)
                trimmed[collection][0].pop(field)
                if validate_snapshot(trimmed) and (collection, field) not in KNOWN_STRICTER_THAN_REGISTRY:
                    with self.subTest(level=collection, field=field):
                        self.assertIn(field, registry_item)

    def test_known_drift_entries_are_still_drift(self) -> None:
        """An allowlist entry must be retired once the registry declares the field."""
        for collection, field in sorted(KNOWN_STRICTER_THAN_REGISTRY):
            with self.subTest(collection=collection, field=field):
                registry_item = set(self.schema["$defs"][ITEM_DEFS[collection]].get("required", []))
                self.assertNotIn(field, registry_item, f"registry now requires {collection}[].{field}; drop it from KNOWN_STRICTER_THAN_REGISTRY")

    def test_vendored_copy_matches_registry_checkout(self) -> None:
        checkout = _registry_checkout()
        if checkout is None:
            self.skipTest("no aine-registry checkout (set AINE_REGISTRY_PATH or use a sibling directory)")
        upstream = checkout / SCHEMA_RELATIVE
        self.assertEqual(
            VENDORED_SCHEMA.read_bytes(),
            upstream.read_bytes(),
            f"fixtures/registry.v1.schema.json drifted from {upstream}; recopy it and update the .SOURCE note",
        )


if __name__ == "__main__":
    unittest.main()
