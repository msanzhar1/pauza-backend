import copy
import json
from pathlib import Path

import pytest

from pauza.regions import RegionImportError, validate_entries

DRAFT = json.loads((Path(__file__).parents[1] / "config" / "regions" / "KG.draft.json").read_text(encoding="utf-8"))


def test_kg_draft_cannot_be_imported_until_verified():
    with pytest.raises(RegionImportError, match="verified_at"):
        validate_entries(DRAFT)


def test_kg_draft_valid_after_manual_verification():
    data = copy.deepcopy(DRAFT)
    for item in data["resources"]:
        item["verified_at"] = "2026-12-01"
        item["active"] = True
    entries = validate_entries(data)
    assert {e["region_code"] for e in entries} == {"KG"}
    assert all(e["source_url"].startswith("https://") for e in entries)


def test_kg_draft_entries_are_inactive():
    assert all(item["active"] is False for item in DRAFT["resources"])


def test_import_requires_source():
    data = copy.deepcopy(DRAFT)
    data["resources"][0].update(verified_at="2026-12-01", source_url="")
    with pytest.raises(RegionImportError, match="source_url"):
        validate_entries(data)
