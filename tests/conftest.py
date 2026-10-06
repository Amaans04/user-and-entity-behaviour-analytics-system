import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))


@pytest.fixture(scope="session")
def small_raw(tmp_path_factory):
    """A half-size synthetic company (24 users, 60 days) shared by the platform tests."""
    from ueba.config import CONFIG
    from ueba.generator import generate_dataset
    raw = tmp_path_factory.mktemp("small") / "raw"
    generate_dataset(raw, copy.deepcopy(CONFIG), n_users_scale=0.5)
    return raw


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Point workspaces, the console database and the service heartbeat at a temp folder."""
    from ueba import auth, service, workspace
    monkeypatch.setattr(workspace, "WS_ROOT", tmp_path / "workspaces")
    monkeypatch.setattr(auth, "CONSOLE_DB", tmp_path / "console.db")
    monkeypatch.setattr(service, "HEARTBEAT", tmp_path / "service.json")
    return tmp_path
