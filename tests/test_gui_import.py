import pytest

pytest.importorskip("PySide6")


def test_gui_module_imports():
    import ransomleak_pro.gui  # noqa: F401
