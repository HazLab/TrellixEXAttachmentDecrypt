"""Unit tests for the recheck poll-ramp parser."""

from trellix_decrypt.recheck import _DEFAULT_RAMP, _parse_ramp


def test_parses_csv_seconds():
    assert _parse_ramp("2,2,3,3,5,5,8") == [2, 2, 3, 3, 5, 5, 8]


def test_ignores_whitespace_and_bad_tokens():
    assert _parse_ramp(" 1 , x , 4 ,, 0 , -2 , 7 ") == [1, 4, 7]


def test_blank_or_unparseable_falls_back_to_default():
    assert _parse_ramp("") == _DEFAULT_RAMP
    assert _parse_ramp("   ") == _DEFAULT_RAMP
    assert _parse_ramp("nope") == _DEFAULT_RAMP
    assert _parse_ramp(None) == _DEFAULT_RAMP
