import crypto_utils


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
