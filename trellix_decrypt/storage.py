"""SQLAlchemy persistence: ORM models + repository.

The repository returns detached ORM instances (``expire_on_commit=False``) whose
loaded attributes stay readable after the session closes, so the FlowEngine can
treat cases as plain value objects.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Enum as SAEnum
from sqlalchemy import ForeignKey, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.pool import StaticPool

from .domain import RECHECKABLE, AlertEvent, FlowState


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return uuid4().hex


class Base(DeclarativeBase):
    pass


class AttachmentCase(Base):
    __tablename__ = "attachment_cases"

    id: Mapped[str] = mapped_column(primary_key=True, default=_uuid)
    queue_id: Mapped[str] = mapped_column(index=True, unique=True)
    recipient: Mapped[str] = mapped_column(index=True)
    sender: Mapped[str | None] = mapped_column(default=None)
    subject: Mapped[str | None] = mapped_column(default=None)
    rule_id: Mapped[int | None] = mapped_column(default=None)
    state: Mapped[FlowState] = mapped_column(SAEnum(FlowState), default=FlowState.RECEIVED)
    attempts: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(default=_now)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)

    events: Mapped[list["EventLog"]] = relationship(back_populates="case", cascade="all, delete-orphan")


class PasswordAttempt(Base):
    __tablename__ = "password_attempts"

    id: Mapped[str] = mapped_column(primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(ForeignKey("attachment_cases.id"), index=True)
    password_hash: Mapped[str] = mapped_column()  # sha256 — never the plaintext
    created_at: Mapped[datetime] = mapped_column(default=_now)


class EventLog(Base):
    __tablename__ = "event_log"

    id: Mapped[str] = mapped_column(primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(ForeignKey("attachment_cases.id"), index=True)
    state: Mapped[FlowState] = mapped_column(SAEnum(FlowState))
    detail: Mapped[str] = mapped_column(default="")
    created_at: Mapped[datetime] = mapped_column(default=_now)

    case: Mapped[AttachmentCase] = relationship(back_populates="events")


def build_session_factory(db_url: str):
    kwargs = {}
    if db_url in ("sqlite://", "sqlite:///:memory:"):  # share one in-memory DB across sessions
        kwargs = dict(connect_args={"check_same_thread": False}, poolclass=StaticPool)
    engine = create_engine(db_url, **kwargs)
    Base.metadata.create_all(engine)
    return sessionmaker(engine, expire_on_commit=False)


class CaseRepository:
    """All persistence the FlowEngine needs, in short committed transactions."""

    def __init__(self, session_factory):
        self._sf = session_factory

    def get_or_create_case(self, event: AlertEvent) -> AttachmentCase:
        with self._sf() as s:
            case = s.scalar(select(AttachmentCase).where(AttachmentCase.queue_id == event.queue_id))
            if case is None:
                case = AttachmentCase(
                    queue_id=event.queue_id, recipient=event.recipient, sender=event.sender,
                    subject=event.subject, rule_id=event.rule_id, state=FlowState.RECEIVED,
                )
                s.add(case)
                s.flush()
                s.add(EventLog(case_id=case.id, state=FlowState.RECEIVED, detail="alert received"))
                s.commit()
            return case

    def get_case(self, case_id: str) -> AttachmentCase | None:
        with self._sf() as s:
            return s.get(AttachmentCase, case_id)

    def set_state(self, case: AttachmentCase, state: FlowState, detail: str = "") -> AttachmentCase:
        with self._sf() as s:
            db_case = s.get(AttachmentCase, case.id)
            db_case.state = state
            s.add(EventLog(case_id=db_case.id, state=state, detail=detail))
            s.commit()
            case.state = state  # keep caller's reference in sync
            return db_case

    def add_attempt(self, case: AttachmentCase, password_hash: str) -> None:
        with self._sf() as s:
            db_case = s.get(AttachmentCase, case.id)
            db_case.attempts += 1
            s.add(PasswordAttempt(case_id=db_case.id, password_hash=password_hash))
            s.commit()
            case.attempts = db_case.attempts

    def list_pending_ids(self) -> list[str]:
        with self._sf() as s:
            return list(s.scalars(select(AttachmentCase.id).where(AttachmentCase.state.in_(RECHECKABLE))))
