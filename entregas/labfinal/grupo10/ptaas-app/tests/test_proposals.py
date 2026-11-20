from harness.poc.proposals import load_proposals


def test_teacher_proposals_are_disabled():
    proposals = load_proposals()
    assert proposals
    assert all(item["enabled"] is True and item["executable"] is False
               and item["review_required"] is True for item in proposals)
