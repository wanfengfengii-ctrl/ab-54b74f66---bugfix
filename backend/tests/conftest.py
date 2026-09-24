import os
import tempfile

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="sealingdesk-test-"))
os.environ.setdefault("STATIC_DIR", tempfile.mkdtemp(prefix="sealingdesk-static-"))

from app import main as web  # noqa: E402
from app.storage import UploadStore  # noqa: E402


@pytest.fixture()
def client(tmp_path):
    web.store = UploadStore(str(tmp_path / "data"))
    web.store.repair_block_limit = None
    yield TestClient(web.app)
    web.store.repair_block_limit = None
