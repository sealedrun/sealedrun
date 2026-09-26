"""SQLAlchemy models and engine setup for the recorder database."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, LargeBinary, String, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)


class Base(DeclarativeBase):
    """Declarative base that collects the recorder tables."""


class BundleRow(Base):
    """An imported bundle: manifest, verification report and the archive as uploaded."""

    __tablename__ = "bundles"

    bundle_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    principal_id: Mapped[str] = mapped_column(String(128), index=True)
    exporter_agent_id: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[str] = mapped_column(String(24))
    imported_at: Mapped[datetime]
    size_bytes: Mapped[int]
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON)
    report: Mapped[dict[str, Any]] = mapped_column(JSON)
    archive: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)

    runs: Mapped[list[RunRow]] = relationship(back_populates="bundle", cascade="all, delete-orphan")


class DelegationRow(Base):
    """A signed Delegation in which a Principal authorises an agent's keys (SPEC section 2)."""

    __tablename__ = "delegations"

    delegation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    principal_id: Mapped[str] = mapped_column(String(128), index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSON)


class RunRow(Base):
    """A run: imported from a verified bundle, or recorded live by this recorder.

    `source` is `imported` or `live`. Live runs have no bundle and their figures are kept
    current on every append. `run_label` is the proxy's X-SealedRun-Run label when the run was
    opened by a labelled proxy call.
    """

    __tablename__ = "runs"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    bundle_id: Mapped[str | None] = mapped_column(
        ForeignKey("bundles.bundle_id"), index=True, nullable=True
    )
    source: Mapped[str] = mapped_column(String(16), default="imported", index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    principal_id: Mapped[str] = mapped_column(String(128), index=True)
    hash_alg: Mapped[str] = mapped_column(String(16))
    started_at: Mapped[str] = mapped_column(String(24))
    ended_at: Mapped[str | None] = mapped_column(String(24), nullable=True)
    record_count: Mapped[int]
    first_seq: Mapped[int]
    last_hash: Mapped[str] = mapped_column(String(96))
    complete: Mapped[bool]
    anchors: Mapped[int]
    labels_sent_to_cloud: Mapped[dict[str, int]] = mapped_column(JSON)
    run_label: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    bundle: Mapped[BundleRow | None] = relationship(back_populates="runs")
    records: Mapped[list[RecordRow]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="RecordRow.seq"
    )


class RecordRow(Base):
    """A signed record; indexed columns are copies of fields in `document`."""

    __tablename__ = "records"

    record_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), index=True)
    seq: Mapped[int]
    kind: Mapped[str] = mapped_column(String(32), index=True)
    occurred_at: Mapped[str] = mapped_column(String(24))
    target_type: Mapped[str] = mapped_column(String(16))
    target_name: Mapped[str] = mapped_column(String(256))
    target_location: Mapped[str | None] = mapped_column(String(16), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16))
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    hash: Mapped[str] = mapped_column(String(96), index=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSON)

    run: Mapped[RunRow] = relationship(back_populates="records")


class PayloadRow(Base):
    """A payload body keyed by its digest, shared by every record that references it."""

    __tablename__ = "payloads"

    digest: Mapped[str] = mapped_column(String(128), primary_key=True)
    hash_alg: Mapped[str] = mapped_column(String(16))
    size_bytes: Mapped[int]
    body: Mapped[bytes] = mapped_column(LargeBinary)


def make_engine(url: str) -> Engine:
    """Create the engine and any missing tables.

    SQLite connections get WAL journaling and foreign key enforcement, and may be used from
    any thread because FastAPI runs sync routes in a thread pool.
    """
    engine = create_engine(
        url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {}
    )
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _pragmas(connection: Any, _: Any) -> None:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return engine


def session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a session factory whose objects stay readable after commit."""
    return sessionmaker(engine, expire_on_commit=False)


def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Yield a session from the factory and close it afterwards."""
    with factory() as session:
        yield session
