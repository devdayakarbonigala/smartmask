"""Create the synthetic demo database on first run so that a fresh clone can run the tests."""

import os

import pytest

from smartmask import config, seed


@pytest.fixture(scope="session", autouse=True)
def demo_database():
    path = config.SQLITE_PATH
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        seed.load_sqlite(path, seed.generate())
