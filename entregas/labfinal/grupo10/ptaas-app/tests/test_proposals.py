import pytest

from harness.poc.catalog import load_catalog
from harness.poc.proposals import load_proposals
from runtime.relevo import ROOT_CHECKS, run_header_review


def test_teacher_proposals_are_disabled():
    proposals = load_proposals()
    assert proposals
    assert all(item["enabled"] is True and item["executable"] is False
               and item["review_required"] is True for item in proposals)


def test_pending_proposals_cannot_reach_sandbox(tmp_path, monkeypatch):
    ids = {item['id'] for item in load_proposals()}
    assert {'PROPOSAL-AUTH-SQLI-001', 'PROPOSAL-SQLI-SEARCH-001'} <= ids
    assert ids.isdisjoint(load_catalog()) and ids.isdisjoint(ROOT_CHECKS)
    monkeypatch.setattr('runtime.relevo.subprocess.run',
                        lambda *a, **kw: pytest.fail('proposal must not reach sandbox'))
    for proposal in ids:
        with pytest.raises(ValueError, match='consulta no habilitada'):
            run_header_review(proposal, tmp_path / 'receipt.json')
