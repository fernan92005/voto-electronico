"""Smoke tests: verifican que los módulos del proyecto importan sin errores."""


def test_import_crypto_utils():
    import src.crypto_utils  # noqa: F401


def test_import_voter_admin_mixnet():
    import src.voter  # noqa: F401
    import src.admin  # noqa: F401
    import src.mixnet  # noqa: F401


def test_import_counter_and_types():
    import src.counter  # noqa: F401
    import src.types  # noqa: F401
