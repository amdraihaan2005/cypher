from typing import Generator
from src.mitre.db import MitreRepository


def get_repo() -> Generator[MitreRepository, None, None]:
    """
    FastAPI dependency that yields a MitreRepository instance.
    Guarantees clean SQLite handle release via context manager teardown on response completion.
    """
    with MitreRepository() as repo:
        yield repo


__all__ = ["get_repo"]
