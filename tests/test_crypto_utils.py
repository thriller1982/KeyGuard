import crypto_utils

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


def test_derive_key_is_stable_for_same_input():
    salt = b"1234567890abcdef"
    key1 = crypto_utils.derive_key("master-password", salt)
    key2 = crypto_utils.derive_key("master-password", salt)
    assert key1 == key2


def test_derive_key_changes_with_different_password():
    salt = b"1234567890abcdef"
    key1 = crypto_utils.derive_key("master-password", salt)
    key2 = crypto_utils.derive_key("different-password", salt)
    assert key1 != key2


def test_derive_key_argon2id_stable():
    salt = b"1234567890abcdef"
    key1 = crypto_utils.derive_key_argon2id("master-password", salt)
    key2 = crypto_utils.derive_key_argon2id("master-password", salt)
    assert key1 == key2
    assert len(key1) == 44  # urlsafe-b64 of 32 bytes


def test_derive_key_argon2id_changes_with_password():
    salt = b"1234567890abcdef"
    key1 = crypto_utils.derive_key_argon2id("master-password", salt)
    key2 = crypto_utils.derive_key_argon2id("different-password", salt)
    assert key1 != key2


def test_derive_key_argon2id_changes_with_salt():
    key1 = crypto_utils.derive_key_argon2id("master-password", b"salt-one-16byte")
    key2 = crypto_utils.derive_key_argon2id("master-password", b"salt-two-16byte!")
    assert key1 != key2


def test_derive_key_argon2id_custom_params():
    salt = b"1234567890abcdef"
    key_default = crypto_utils.derive_key_argon2id("pw", salt)
    key_custom = crypto_utils.derive_key_argon2id(
        "pw", salt, {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
    )
    assert key_default != key_custom


def test_derive_key_for_kdf_argon2id_dispatches():
    salt = b"1234567890abcdef"
    spec = {
        "algorithm": "argon2id",
        "salt": salt.hex(),
        "params": crypto_utils.DEFAULT_ARGON2_PARAMS,
    }
    key = crypto_utils.derive_key_for_kdf("pw", salt, spec)
    assert key == crypto_utils.derive_key_argon2id("pw", salt, spec["params"])


def test_derive_key_for_kdf_pbkdf2_dispatches():
    salt = b"1234567890abcdef"
    spec = {
        "algorithm": "pbkdf2_sha256",
        "salt": salt.hex(),
        "params": {"iterations": 600000},
    }
    key = crypto_utils.derive_key_for_kdf("pw", salt, spec)
    assert key == crypto_utils.derive_key("pw", salt)


def test_derive_key_for_kdf_unknown_algorithm_raises():
    import pytest

    with pytest.raises(ValueError):
        crypto_utils.derive_key_for_kdf("pw", b"salt-16bytes!!!!", {"algorithm": "scrypt"})


def test_default_argon2_params_sanity():
    p = crypto_utils.DEFAULT_ARGON2_PARAMS
    assert p["time_cost"] >= 1
    assert p["memory_cost_kib"] >= 8192
    assert p["parallelism"] >= 1


def test_generate_totp_rfc6238_vectors():
    # RFC 6238 standard test vector (ASCII '12345678901234567890' in Base32)
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    code, rem, status = crypto_utils.generate_totp(secret, for_time=59)
    assert status == "ok"
    assert code == "287082"
    assert rem == 1

    code, rem, status = crypto_utils.generate_totp(secret, for_time=1111111109)
    assert status == "ok"
    assert code == "081804"

    code, rem, status = crypto_utils.generate_totp(secret, for_time=1234567890)
    assert status == "ok"
    assert code == "005924"


def test_generate_totp_handles_spaces_and_lowercase():
    secret = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"
    code, rem, status = crypto_utils.generate_totp(secret, for_time=59)
    assert status == "ok"
    assert code == "287082"


def test_generate_totp_empty_and_invalid():
    code, rem, status = crypto_utils.generate_totp("")
    assert status == "empty"
    assert code == ""

    code, rem, status = crypto_utils.generate_totp("   ")
    assert status == "empty"

    code, rem, status = crypto_utils.generate_totp("invalid189!!!")
    assert status == "invalid"
    assert code == ""
