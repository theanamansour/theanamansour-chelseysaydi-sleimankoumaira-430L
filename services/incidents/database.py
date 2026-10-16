from database.config import get_database_path
from database.connection import get_db
from database.init_db import init_database

__all__ = ["get_database_path", "get_db", "init_db"]


def init_db(database_path=None):
    return init_database("incidents", database_path)


if __name__ == "__main__":
    print(f"Incident tables ready in: {init_db()}")
