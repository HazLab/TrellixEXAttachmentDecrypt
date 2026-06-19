"""TLS mode -> aiosmtplib argument mapping."""

from __future__ import annotations

from trellix_decrypt.mailer import tls_kwargs


def test_tls_modes():
    assert tls_kwargs("opportunistic") == {"start_tls": None, "use_tls": False}
    assert tls_kwargs("starttls") == {"start_tls": True, "use_tls": False}
    assert tls_kwargs("none") == {"start_tls": False, "use_tls": False}
    assert tls_kwargs("ssl") == {"start_tls": False, "use_tls": True}


def test_tls_mode_defaults_and_normalizes():
    assert tls_kwargs("") == {"start_tls": None, "use_tls": False}        # default opportunistic
    assert tls_kwargs("BOGUS") == {"start_tls": None, "use_tls": False}   # unknown -> opportunistic
    assert tls_kwargs(" STARTTLS ") == {"start_tls": True, "use_tls": False}  # trimmed/cased
