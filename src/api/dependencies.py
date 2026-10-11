from typing import Generator
from src.mitre.db import MitreRepository


def get_repo() -> Generator[MitreRepository, None, None]:
    with MitreRepository() as repo:
        yield repo


__all__ = ["get_repo"]
