"""SQLAlchemy models and engine setup for the recorder database."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Column,
    ForeignKey,
    LargeBinary,
    String,
    create_engine,
    event,
    inspect,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)

log = logging.getLogger("sealedrun.recorder")


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
    opened by a labelled proxy call; `last_anchor_at` is the time of the run's latest anchor
    record.
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
    labels_self_reported: Mapped[dict[str, int]] = mapped_column(JSON, default=dict)
    run_label: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    last_anchor_at: Mapped[str | None] = mapped_column(String(24), nullable=True)

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


def _default_value(column: Column[Any]) -> Any:
    """Return the value the model gives a column when a row does not set it."""
    default = column.default
    if default is None or not (default.is_scalar or default.is_callable):
        raise RuntimeError(
            f"database upgrade: {column.table.name}.{column.name} is required and has no default"
        )
    return default.arg(None) if default.is_callable else default.arg  # type: ignore[attr-defined]


def ensure_schema(engine: Engine) -> list[str]:
    """Add the columns the models have and an older database lacks.

    A database written by an earlier release keeps its rows: each missing column is added,
    rows that predate a required column get the model's default, and indexes on the new
    columns are created. Columns are never dropped, renamed or retyped. Returns the columns
    added as `table.column`.
    """
    added: list[str] = []
    quote = engine.dialect.identifier_preparer
    with engine.begin() as connection:
        existing = {
            table.name: {column["name"] for column in inspect(connection).get_columns(table.name)}
            for table in Base.metadata.sorted_tables
        }
        for table in Base.metadata.sorted_tables:
            missing = [
                column for column in table.columns if column.name not in existing[table.name]
            ]
            for column in missing:
                name = quote.format_table(table)
                connection.execute(
                    text(
                        f"ALTER TABLE {name} ADD COLUMN {quote.format_column(column)} "
                        f"{column.type.compile(dialect=engine.dialect)}"
                    )
                )
                if not column.nullable:
                    connection.execute(
                        table.update()
                        .where(column.is_(None))
                        .values({column: _default_value(column)})
                    )
                    if engine.dialect.name != "sqlite":
                        connection.execute(
                            text(
                                f"ALTER TABLE {name} ALTER COLUMN {quote.format_column(column)} "
                                "SET NOT NULL"
                            )
                        )
                added.append(f"{table.name}.{column.name}")
            names = {column.name for column in missing}
            for index in table.indexes:
                if names & {column.name for column in index.columns}:
                    index.create(connection, checkfirst=True)
    return added


def make_engine(url: str) -> Engine:
    """Create the engine, any missing tables and any columns an older database lacks.

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
    added = ensure_schema(engine)
    if added:
        log.warning("database upgraded, columns added: %s", ", ".join(added))
    return engine


def session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a session factory whose objects stay readable after commit."""
    return sessionmaker(engine, expire_on_commit=False)


def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Yield a session from the factory and close it afterwards."""
    with factory() as session:
        yield session
