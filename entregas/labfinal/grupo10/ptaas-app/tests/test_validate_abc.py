import pytest

from runtime import validate_abc


@pytest.mark.parametrize(('approval', 'reason'), [
    (None, 'reviewer_approval_required'),
    ('0' * 64, 'approval_hash_mismatch'),
])
def test_unapproved_receipt_never_starts_docker(tmp_path, monkeypatch, approval, reason):
    receipt = tmp_path / 'unapproved.json'
    receipt.write_bytes(b'{}')
    monkeypatch.setattr(validate_abc.subprocess, 'run',
                        lambda *args, **kwargs: pytest.fail('Docker started without matching approval'))
    with pytest.raises(ValueError, match=reason):
        validate_abc.validate(receipt, approval)
