import os
from dataclasses import replace
from pathlib import Path

import pytest

from posture.filtering import Filters
from posture.parsing import ReportError
from posture.storage import ReportStore, StorageFull

from .test_domain import sample


@pytest.fixture
def store():
    storage = ReportStore()
    yield storage
    storage.close()


def test_storage_limits_dedup_and_cleanup(store):
    workspace = "a" * 32
    store.ensure(workspace, seed=False)
    key, added = store.add(workspace, sample())
    assert added and store.get(workspace, key).report == sample()
    assert not store.add(workspace, sample())[1]
    assert store.get(workspace, "../bad") is None
    assert store.get("b" * 32, key) is None
    with pytest.raises(ReportError, match="different contents"):
        store.add(workspace, replace(sample(), source="other"))
    store.max_reports = 1
    with pytest.raises(StorageFull, match="at most"):
        store.add(workspace, replace(sample(), report_id="another"))
    os.utime(store.root / workspace, (1, 1))
    store.ensure("b" * 32, seed=False)
    assert not (store.root / workspace).exists()
    store.max_workspaces = 1
    with pytest.raises(StorageFull, match="workspace limit"):
        store.ensure("c" * 32, seed=False)
    assert store.list("d" * 32) == []
    with pytest.raises(ReportError, match="workspace identifier"):
        store.ensure("../bad")


def test_storage_errors_leave_no_partial_report(store, monkeypatch):
    workspace = "a" * 32
    store.ensure(workspace, seed=False)
    original = Path.replace

    def failed_replace(self, target):
        raise OSError("simulated temp volume full")

    monkeypatch.setattr(Path, "replace", failed_replace)
    with pytest.raises(StorageFull, match="unavailable"):
        store.add(workspace, sample())
    assert list((store.root / workspace).iterdir()) == []
    monkeypatch.setattr(Path, "replace", original)
    huge = replace(sample().findings[0], evidence="x" * 1_048_576)
    with pytest.raises(ReportError, match="Normalized"):
        store.add(workspace, replace(sample(), findings=(huge,)))


def test_filters_search_sort_and_exports():
    report = sample()
    assert len(Filters(account="demo-west").apply(report)) == 3
    assert len(Filters(check_type="stale-key").apply(report)) == 1
    assert not Filters(q="no-match").apply(report)
    assert Filters(q="WILDCARD").apply(report)
    first = Filters(sort="title").apply(report)
    reverse = Filters(sort="title", order="desc").apply(report)
    assert first == list(reversed(reverse))
    assert Filters().to_dict()["sort"] == "risk"
