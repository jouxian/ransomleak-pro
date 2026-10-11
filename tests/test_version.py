from pathlib import Path
import tomllib

from ransomleak_pro.config import APP_VERSION


def test_package_and_runtime_versions_match():
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    assert data["project"]["version"] == APP_VERSION
