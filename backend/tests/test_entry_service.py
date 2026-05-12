# -*- coding: utf-8 -*-
"""
Тесты CRUD Сервиса — async E2EE envelope API (v2.0.0+).

Проверяют работоспособность EntryService с клиент-зашифрованными envelopes.
"""

import base64
import secrets

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from backend.core.audit_logger import Base as AuditBase
from backend.database.models import User, PasswordEntry
from backend.database.schemas import EntryEnvelopeCreateSchema
from backend.database.entry_service import EntryService, EntryNotFoundError, EntryConflictError


@pytest_asyncio.fixture(scope="module")
async def async_engine():
    """Async in-memory SQLite engine with all tables."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(AuditBase.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def async_session(async_engine) -> AsyncSession:
    """Per-test async session with auto-rollback."""
    session_maker = async_sessionmaker(async_engine, expire_on_commit=False)
    async with session_maker() as session:
        yield session


@pytest_asyncio.fixture
async def user_id(async_session: AsyncSession) -> int:
    """Create a test user and return its id."""
    import uuid
    suffix = uuid.uuid4().hex[:8]
    u = User(
        username=f"test_{suffix}",
        email=f"{suffix}@test.com",
        password_hash="test",
        salt=b"12345678",
        wrapped_master_key_cipher=b"\x00" * 32,
        wrapped_master_key_nonce=b"\x00" * 12,
        wrapped_master_key_tag=b"\x00" * 16,
    )
    async_session.add(u)
    await async_session.commit()
    return u.id


def _make_envelope():
    """Generate valid base64-encoded E2EE envelope fields."""
    ciphertext = base64.b64encode(secrets.token_bytes(32)).decode()
    iv = base64.b64encode(secrets.token_bytes(12)).decode()
    auth_tag = base64.b64encode(secrets.token_bytes(16)).decode()
    return ciphertext, iv, auth_tag


@pytest.mark.asyncio
async def test_create_entry(async_session: AsyncSession, user_id: int):
    """Creating an E2EE envelope entry stores opaque blobs in the DB."""
    service = EntryService(async_session)
    ciphertext, iv, auth_tag = _make_envelope()
    schema = EntryEnvelopeCreateSchema(
        title_search="blind_index_abc",
        ciphertext=ciphertext,
        iv=iv,
        auth_tag=auth_tag,
    )
    entry = await service.create_entry_async(user_id, schema)
    assert entry.id is not None
    assert entry.ciphertext is not None
    assert entry.iv is not None
    assert entry.auth_tag is not None
    assert entry.title_search == "blind_index_abc"


@pytest.mark.asyncio
async def test_get_entry_envelope(async_session: AsyncSession, user_id: int):
    """Retrieving an entry returns the same envelope data."""
    service = EntryService(async_session)
    ciphertext, iv, auth_tag = _make_envelope()
    schema = EntryEnvelopeCreateSchema(
        title_search="test_entry",
        ciphertext=ciphertext,
        iv=iv,
        auth_tag=auth_tag,
    )
    created = await service.create_entry_async(user_id, schema)

    retrieved = await service.get_entry_envelope_async(user_id, created.id)
    assert retrieved.ciphertext == ciphertext
    assert retrieved.iv == iv
    assert retrieved.auth_tag == auth_tag
    assert retrieved.title_search == "test_entry"


@pytest.mark.asyncio
async def test_delete_entry_soft(async_session: AsyncSession, user_id: int):
    """Soft-deleting an entry hides it from reads but keeps it in DB."""
    service = EntryService(async_session)
    ciphertext, iv, auth_tag = _make_envelope()
    schema = EntryEnvelopeCreateSchema(
        title_search="to_delete",
        ciphertext=ciphertext,
        iv=iv,
        auth_tag=auth_tag,
    )
    created = await service.create_entry_async(user_id, schema)

    assert await service.delete_entry_async(user_id, created.id) is True

    # Should be invisible to normal reads
    with pytest.raises(EntryNotFoundError):
        await service.get_entry_envelope_async(user_id, created.id)

    # But still present in DB with is_deleted=True
    result = await async_session.execute(
        select(PasswordEntry).where(PasswordEntry.id == created.id)
    )
    db_entry = result.scalar_one()
    assert db_entry is not None
    assert db_entry.is_deleted is True
    assert db_entry.deleted_at is not None


@pytest.mark.asyncio
async def test_list_entries_pagination(async_session: AsyncSession, user_id: int):
    """list_entries_async respects skip/limit."""
    service = EntryService(async_session)
    for i in range(5):
        ciphertext, iv, auth_tag = _make_envelope()
        schema = EntryEnvelopeCreateSchema(
            title_search=f"entry_{i}",
            ciphertext=ciphertext,
            iv=iv,
            auth_tag=auth_tag,
        )
        await service.create_entry_async(user_id, schema)

    all_entries = await service.list_entries_async(user_id, skip=0, limit=100)
    assert len(all_entries) == 5

    paginated = await service.list_entries_async(user_id, skip=2, limit=2)
    assert len(paginated) == 2


@pytest.mark.asyncio
async def test_update_entry(async_session: AsyncSession, user_id: int):
    """Updating envelope fields changes stored blobs."""
    service = EntryService(async_session)
    ciphertext, iv, auth_tag = _make_envelope()
    schema = EntryEnvelopeCreateSchema(
        title_search="original",
        ciphertext=ciphertext,
        iv=iv,
        auth_tag=auth_tag,
    )
    created = await service.create_entry_async(user_id, schema)

    new_ct, new_iv, new_tag = _make_envelope()
    from backend.database.schemas import EntryEnvelopeUpdateSchema
    update = EntryEnvelopeUpdateSchema(
        ciphertext=new_ct,
        iv=new_iv,
        auth_tag=new_tag,
    )
    updated = await service.update_entry_async(user_id, created.id, update)
    import base64
    assert updated.ciphertext == base64.b64decode(new_ct)
    assert updated.iv == base64.b64decode(new_iv)
    assert updated.auth_tag == base64.b64decode(new_tag)


@pytest.mark.asyncio
async def test_entry_not_found(async_session: AsyncSession, user_id: int):
    """Accessing a non-existent entry raises EntryNotFoundError."""
    service = EntryService(async_session)
    with pytest.raises(EntryNotFoundError):
        await service.get_entry_envelope_async(user_id, 99999)


@pytest.mark.asyncio
async def test_entry_belongs_to_wrong_user(async_session: AsyncSession, user_id: int):
    """Users cannot read each other's entries."""
    # Create second user
    other = User(
        username="other",
        email="other@test.com",
        password_hash="x",
        salt=b"00000000",
        wrapped_master_key_cipher=b"\x00" * 32,
        wrapped_master_key_nonce=b"\x00" * 12,
        wrapped_master_key_tag=b"\x00" * 16,
    )
    async_session.add(other)
    await async_session.commit()

    service = EntryService(async_session)
    ciphertext, iv, auth_tag = _make_envelope()
    schema = EntryEnvelopeCreateSchema(
        title_search="private",
        ciphertext=ciphertext,
        iv=iv,
        auth_tag=auth_tag,
    )
    created = await service.create_entry_async(user_id, schema)

    with pytest.raises(EntryNotFoundError):
        await service.get_entry_envelope_async(other.id, created.id)


@pytest.mark.asyncio
async def test_entry_conflict_error(async_session: AsyncSession, user_id: int):
    service = EntryService(async_session)
    ciphertext, iv, auth_tag = _make_envelope()
    schema = EntryEnvelopeCreateSchema(
        title_search="conflict_test",
        ciphertext=ciphertext,
        iv=iv,
        auth_tag=auth_tag,
    )
    created = await service.create_entry_async(user_id, schema)

    from datetime import datetime, timezone, timedelta
    from backend.database.schemas import EntryEnvelopeUpdateSchema

    old_time = datetime(2020, 1, 1)
    update = EntryEnvelopeUpdateSchema(title_search="new_title")
    with pytest.raises(EntryConflictError):
        await service.update_entry_async(user_id, created.id, update, client_updated_at=old_time)


@pytest.mark.asyncio
async def test_update_empty_dict_returns_entry(async_session: AsyncSession, user_id: int):
    service = EntryService(async_session)
    ciphertext, iv, auth_tag = _make_envelope()
    schema = EntryEnvelopeCreateSchema(
        title_search="empty_update",
        ciphertext=ciphertext,
        iv=iv,
        auth_tag=auth_tag,
    )
    created = await service.create_entry_async(user_id, schema)

    from backend.database.schemas import EntryEnvelopeUpdateSchema
    update = EntryEnvelopeUpdateSchema()
    result = await service.update_entry_async(user_id, created.id, update)
    assert result.id == created.id


@pytest.mark.asyncio
async def test_partial_core_fields_raises(async_session: AsyncSession, user_id: int):
    service = EntryService(async_session)
    ciphertext, iv, auth_tag = _make_envelope()
    schema = EntryEnvelopeCreateSchema(
        title_search="partial_core",
        ciphertext=ciphertext,
        iv=iv,
        auth_tag=auth_tag,
    )
    created = await service.create_entry_async(user_id, schema)

    from backend.database.schemas import EntryEnvelopeUpdateSchema
    update = EntryEnvelopeUpdateSchema(ciphertext=_make_envelope()[0], iv=_make_envelope()[1])
    with pytest.raises(ValueError, match="must be updated together"):
        await service.update_entry_async(user_id, created.id, update)


@pytest.mark.asyncio
async def test_update_title_search(async_session: AsyncSession, user_id: int):
    service = EntryService(async_session)
    ciphertext, iv, auth_tag = _make_envelope()
    schema = EntryEnvelopeCreateSchema(
        title_search="old_title",
        ciphertext=ciphertext,
        iv=iv,
        auth_tag=auth_tag,
    )
    created = await service.create_entry_async(user_id, schema)

    from backend.database.schemas import EntryEnvelopeUpdateSchema
    update = EntryEnvelopeUpdateSchema(title_search="new_title_idx")
    updated = await service.update_entry_async(user_id, created.id, update)
    assert updated.title_search == "new_title_idx"


@pytest.mark.asyncio
async def test_purge_deleted_entries(async_session: AsyncSession, user_id: int):
    service = EntryService(async_session)
    ciphertext, iv, auth_tag = _make_envelope()
    schema = EntryEnvelopeCreateSchema(
        title_search="purge_me",
        ciphertext=ciphertext,
        iv=iv,
        auth_tag=auth_tag,
    )
    created = await service.create_entry_async(user_id, schema)
    await service.delete_entry_async(user_id, created.id)

    from datetime import datetime, timezone, timedelta
    from backend.database.models import PasswordEntry as PE

    async_session.add(PE(
        user_id=user_id,
        title_search="old",
        ciphertext=b"x",
        iv=b"y",
        auth_tag=b"z",
        is_deleted=True,
        deleted_at=datetime.now(timezone.utc) - timedelta(days=60),
        title_cipher="",
        title_nonce="",
        password_cipher="",
        password_nonce="",
    ))
    await async_session.commit()

    purged = await service.purge_deleted_entries_async(user_id, older_than_days=30)
    assert purged >= 1


@pytest.mark.asyncio
async def test_change_master_password(async_session: AsyncSession):
    from backend.core.crypto_bridge import bridge as crypto_bridge, zeroize_mutable_buffer

    salt = secrets.token_bytes(16)
    password_buf = bytearray(b"OldPass123!")
    master_key = crypto_bridge.argon2_derive_key(password_buf, salt, wipe_password=True)

    import hashlib
    derived_bytes = crypto_bridge.locked_buffer_to_bytearray(master_key)
    pw_hash = hashlib.sha256(derived_bytes).hexdigest()
    zeroize_mutable_buffer(derived_bytes)
    master_key.close()

    user = User(
        username="changepw_user",
        email="changepw@test.com",
        password_hash=pw_hash,
        salt=salt,
        wrapped_master_key_cipher=b"\x00" * 32,
        wrapped_master_key_nonce=b"\x00" * 12,
        wrapped_master_key_tag=b"\x00" * 16,
    )
    async_session.add(user)
    await async_session.commit()
    await async_session.refresh(user)

    service = EntryService(async_session)
    await service.change_master_password_async(user.id, "OldPass123!", "NewPass456!")

    await async_session.refresh(user)
    old_salt = salt
    assert user.salt != old_salt
    assert user.password_hash != pw_hash
