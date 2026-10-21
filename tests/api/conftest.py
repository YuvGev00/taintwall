from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from taintwall.api import create_app
from taintwall.api.app import Settings


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app(Settings(database_url="sqlite://", detector="noop"))) as c:
        yield c
