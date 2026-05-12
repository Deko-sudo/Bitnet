import sqlite3
from typing import Any

def optimize_sqlite_pragma(dbapi_connection: Any) -> None:
    """
    Apply SQLite performance and safety PRAGMAs on raw DBAPI connections.

    Designed as an event listener for SQLAlchemy engines:
        event.listen(engine, "connect", optimize_sqlite_pragma)
    """
    if isinstance(dbapi_connection, sqlite3.Connection):
        # WAL mode allows concurrent readers with a single writer
        dbapi_connection.execute("PRAGMA journal_mode=WAL")
        # NORMAL sync gives durability without the full overhead
        dbapi_connection.execute("PRAGMA synchronous=NORMAL")
        # 64MB page cache
        dbapi_connection.execute("PRAGMA cache_size=-65536")
        # Temp tables in memory
        dbapi_connection.execute("PRAGMA temp_store=MEMORY")
        # Enable foreign key enforcement
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
        # Memory-mapped I/O for read performance
        dbapi_connection.execute("PRAGMA mmap_size=268435456")
        # Optimal page size (32KB)
        dbapi_connection.execute("PRAGMA page_size=32768")

