"""Opens connections to the shared SQLite database."""
import sqlite3


def get_connection(database_path):
    """Return an open connection. The caller is responsible for closing it."""
    connection = sqlite3.connect(database_path)
    # Rows behave like dictionaries, so we can write row["severity"] instead of row[4].
    connection.row_factory = sqlite3.Row
    # SQLite only enforces foreign keys when this is switched on for each connection.
    connection.execute("PRAGMA foreign_keys = ON")
    return connection
