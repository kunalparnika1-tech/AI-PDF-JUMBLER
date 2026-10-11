import sys
from pathlib import Path

import pytest

# Make the src layout importable without installation.
SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from disposal.config import Config  # noqa: E402


@pytest.fixture
def config(tmp_path):
    cfg = Config(data_dir=tmp_path / "state")
    # Keep scrypt cheap so tests are fast; production uses the defaults.
    cfg.scrypt_n = 2 ** 10
    cfg.ensure_dirs()
    return cfg
