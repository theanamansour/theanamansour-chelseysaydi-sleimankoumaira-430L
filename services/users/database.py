
from database.connection import get_db
from database.init_db import init_database


def init_db():
    return init_database()


if __name__ == "__main__":
    init_db()
    print("Users database created successfully.")
