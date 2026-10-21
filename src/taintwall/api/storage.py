"""Repository layer: sessions and an append-only event log. SQLite by default, Postgres via URL."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Engine, Float, Integer, String, Text, create_engine, event, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


class SessionRow(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    suite: Mapped[str] = mapped_column(String(64))
    user_prompt: Mapped[str] = mapped_column(Text)
    created_at: Mapped[float] = mapped_column(Float)


class EventRow(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(32), index=True)
    ts: Mapped[float] = mapped_column(Float)
    kind: Mapped[str] = mapped_column(String(16))
    tool_name: Mapped[str] = mapped_column(String(128))
    payload: Mapped[str] = mapped_column(Text)
    decision: Mapped[str] = mapped_column(Text)


@dataclass(frozen=True)
class SessionRecord:
    id: str
    suite: str
    user_prompt: str
    created_at: float


@dataclass(frozen=True)
class EventRecord:
    seq: int
    ts: float
    kind: str
    tool_name: str
    payload: dict[str, Any]
    decision: dict[str, Any]


def make_engine(url: str) -> Engine:
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    if not url.startswith("sqlite"):
        return create_engine(url, pool_pre_ping=True)
    if ":memory:" in url or url == "sqlite://":
        engine = create_engine(url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
    else:
        engine = create_engine(url, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_conn: Any, _: Any) -> None:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()

    return engine


class Repository:
    def __init__(self, url: str) -> None:
        self.engine = make_engine(url)
        Base.metadata.create_all(self.engine)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    def ping(self) -> bool:
        with self._sessions() as db:
            db.execute(select(1))
        return True

    def create_session(self, suite: str, user_prompt: str) -> SessionRecord:
        row = SessionRow(id=uuid.uuid4().hex, suite=suite, user_prompt=user_prompt, created_at=time.time())
        with self._sessions.begin() as db:
            db.add(row)
        return SessionRecord(row.id, row.suite, row.user_prompt, row.created_at)

    def get_session(self, session_id: str) -> SessionRecord | None:
        with self._sessions() as db:
            row = db.get(SessionRow, session_id)
            return SessionRecord(row.id, row.suite, row.user_prompt, row.created_at) if row else None

    def add_event(
        self, session_id: str, kind: str, tool_name: str, payload: dict[str, Any], decision: dict[str, Any]
    ) -> None:
        with self._sessions.begin() as db:
            db.add(
                EventRow(
                    session_id=session_id,
                    ts=time.time(),
                    kind=kind,
                    tool_name=tool_name,
                    payload=json.dumps(payload),
                    decision=json.dumps(decision),
                )
            )

    def events(self, session_id: str, kind: str | None = None) -> list[EventRecord]:
        stmt = select(EventRow).where(EventRow.session_id == session_id).order_by(EventRow.id)
        if kind is not None:
            stmt = stmt.where(EventRow.kind == kind)
        with Session(self.engine) as db:
            rows = db.scalars(stmt).all()
            return [
                EventRecord(i, r.ts, r.kind, r.tool_name, json.loads(r.payload), json.loads(r.decision))
                for i, r in enumerate(rows)
            ]
