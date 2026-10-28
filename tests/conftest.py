from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from logsentinel.app import create_app

SAMPLES = Path(__file__).parents[1] / "samples"


@pytest.fixture
def client(tmp_path):
    with TestClient(
        create_app(tmp_path / "events.db"), base_url="http://localhost"
    ) as test_client:
        yield test_client


@pytest.fixture
def samples():
    return SAMPLES
