# -*- coding: utf-8 -*-
"""
Search Engine — Zero-Trust blind-index exact-match search over E2EE entries.

Architecture
------------
Instead of decrypting every row into RAM for filtering, the service uses a
deterministic HMAC ("blind index") derived from the user's query and master key.
The blind index is compared against the indexed ``title_search`` column in SQL.
No plaintext titles ever leave the encrypted storage layer.

The ``title_search`` column is maintained by the entry CRUD service; it
carries ``hex(HMAC-SHA256(title, master_key))``.  Because HMAC is deterministic,
the same title always yields the same blind index, enabling fast, exact-match
DB queries without ever decrypting ciphertext.

Security guarantees
-------------------
* Query string is copied into a ``bytearray``, hashed, then immediately wiped.
* No decrypted data is returned — only the ``PasswordEntry`` ORM objects (the
caller must NOT decrypt unless strictly necessary).
* Pagination prevents unbounded result sets.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.crypto_bridge import LockedBuffer
from backend.core.encryption_helper import generate_search_index
from backend.database.models import PasswordEntry


class SearchService:
    """Async search service backed by blind HMAC indices."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def search_by_title(
        self,
        user_id: int,
        query: str,
        master_key: LockedBuffer,
        *,
        limit: int = 50,
        offset: int = 0,
        sort_by: str = "updated_at",
        sort_order: str = "desc",
        created_after: Optional[datetime] = None,
        updated_after: Optional[datetime] = None,
    ) -> list[PasswordEntry]:
        """
        Search active entries by exact blind-index match on *title_search*.

        Parameters
        ----------
        user_id:
            Owner of the entries.
        query:
            Plain-text title query.  Converted to ``bytearray``, hashed, then
            zeroised inside ``generate_search_index``.
        master_key:
            The user's master encryption key (needed for HMAC derivation).
        limit / offset:
            Pagination controls.
        sort_by:
            ``created_at`` or ``updated_at``.
        sort_order:
            ``asc`` or ``desc``.
        created_after:
            Optional lower bound on ``created_at``.
        updated_after:
            Optional lower bound on ``updated_at``.

        Returns
        -------
        A list of ``PasswordEntry`` ORM instances that match the blind index.
        """
        # Derive deterministic blind index from query + master key.
        # generate_search_index wipes the bytearray for us.
        query_buf = bytearray(query.encode("utf-8"))
        blind_index = generate_search_index(master_key, query_buf)

        stmt = select(PasswordEntry).where(
            PasswordEntry.user_id == user_id,
            PasswordEntry.is_deleted == False,
            PasswordEntry.title_search == blind_index,
        )

        if created_after is not None:
            stmt = stmt.where(PasswordEntry.created_at >= created_after)
        if updated_after is not None:
            stmt = stmt.where(PasswordEntry.updated_at >= updated_after)

        order_col = PasswordEntry.updated_at
        if sort_by == "created_at":
            order_col = PasswordEntry.created_at

        if sort_order == "desc":
            stmt = stmt.order_by(order_col.desc())
        else:
            stmt = stmt.order_by(order_col.asc())

        stmt = stmt.limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_title(
        self,
        user_id: int,
        query: str,
        master_key: LockedBuffer,
    ) -> int:
        """Return the total number of active entries matching the blind index."""
        query_buf = bytearray(query.encode("utf-8"))
        blind_index = generate_search_index(master_key, query_buf)

        stmt = select(PasswordEntry).where(
            PasswordEntry.user_id == user_id,
            PasswordEntry.is_deleted == False,
            PasswordEntry.title_search == blind_index,
        )
        result = await self._session.execute(stmt)
        return len(result.scalars().all())
