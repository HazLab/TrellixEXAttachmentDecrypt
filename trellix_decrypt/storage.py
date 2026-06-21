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

from .domain import RECHECKABLE, TERMINAL, AlertEvent, FlowState


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
    alert_name: Mapped[str | None] = mapped_column(default=None)
    malware_name: Mapped[str | None] = mapped_column(default=None)
    state: Mapped[FlowState] = mapped_column(SAEnum(FlowState), default=FlowState.RECEIVED)
    attempts: Mapped[int] = mapped_column(default=0)
    notify_attempts: Mapped[int] = mapped_column(default=0)
    resubmit_attempts: Mapped[int] = mapped_column(default=0)
    pwd_enc: Mapped[str | None] = mapped_column(default=None)  # encrypted; held only until resubmitted
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


class Setting(Base):
    """Key/value store for UI-editable config overrides (secrets stored encrypted)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(primary_key=True)
    value: Mapped[str] = mapped_column(default="")
    is_secret: Mapped[bool] = mapped_column(default=False)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)


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
                    queue_id=event.queue_id, recipient=", ".join(event.recipients),
                    sender=event.sender, subject=event.subject, alert_name=event.alert_name,
                    malware_name=(event.malware_names[0] if event.malware_names else None),
                    state=FlowState.RECEIVED,
                )
                s.add(case)
                s.flush()
                s.add(EventLog(case_id=case.id, state=FlowState.RECEIVED, detail="alert received"))
                s.commit()
            else:
                # Same email re-notified (e.g. one alert per recipient): merge any new
                # To addresses so the one case holds the full recipient set.
                merged = _merge_recipients(case.recipient, event.recipients)
                if merged != case.recipient:
                    case.recipient = merged
                    s.commit()
            return case

    def get_case(self, case_id: str) -> AttachmentCase | None:
        with self._sf() as s:
            return s.get(AttachmentCase, case_id)

    def find_case_by_queue_id(self, queue_id: str) -> AttachmentCase | None:
        with self._sf() as s:
            return s.scalar(select(AttachmentCase).where(AttachmentCase.queue_id == queue_id))

    def set_state(self, case: AttachmentCase, state: FlowState, detail: str = "") -> AttachmentCase:
        with self._sf() as s:
            db_case = s.get(AttachmentCase, case.id)
            db_case.state = state
            s.add(EventLog(case_id=db_case.id, state=state, detail=detail))
            s.commit()
            case.state = state  # keep caller's reference in sync
            return db_case

    def record_password_hash(self, case: AttachmentCase, password_hash: str) -> None:
        """Audit trail of submitted passwords (hashes only). Does NOT count a failure."""
        with self._sf() as s:
            s.add(PasswordAttempt(case_id=case.id, password_hash=password_hash))
            s.commit()

    def increment_attempts(self, case: AttachmentCase) -> None:
        """Count one confirmed wrong-password round (failed extraction after resubmit)."""
        with self._sf() as s:
            db_case = s.get(AttachmentCase, case.id)
            db_case.attempts += 1
            s.commit()
            case.attempts = db_case.attempts

    def list_pending_ids(self) -> list[str]:
        with self._sf() as s:
            return list(s.scalars(select(AttachmentCase.id).where(AttachmentCase.state.in_(RECHECKABLE))))

    def increment_notify_attempts(self, case: AttachmentCase) -> None:
        with self._sf() as s:
            db_case = s.get(AttachmentCase, case.id)
            db_case.notify_attempts += 1
            s.commit()
            case.notify_attempts = db_case.notify_attempts

    def list_notify_failed_ids(self, max_attempts: int) -> list[str]:
        with self._sf() as s:
            return list(s.scalars(select(AttachmentCase.id).where(
                AttachmentCase.state == FlowState.NOTIFY_FAILED,
                AttachmentCase.notify_attempts < max_attempts)))

    def store_password(self, case: AttachmentCase, pwd_enc: str) -> None:
        with self._sf() as s:
            db_case = s.get(AttachmentCase, case.id)
            db_case.pwd_enc = pwd_enc
            s.commit()
            case.pwd_enc = pwd_enc

    def clear_password(self, case: AttachmentCase) -> None:
        with self._sf() as s:
            db_case = s.get(AttachmentCase, case.id)
            db_case.pwd_enc = None
            s.commit()
            case.pwd_enc = None

    def increment_resubmit_attempts(self, case: AttachmentCase) -> None:
        with self._sf() as s:
            db_case = s.get(AttachmentCase, case.id)
            db_case.resubmit_attempts += 1
            s.commit()
            case.resubmit_attempts = db_case.resubmit_attempts

    def list_resubmit_pending_ids(self, max_attempts: int) -> list[str]:
        """Cases awaiting/failed EX resubmission that still hold the password and
        are under the retry cap."""
        with self._sf() as s:
            return list(s.scalars(select(AttachmentCase.id).where(
                AttachmentCase.state.in_((FlowState.PASSWORD_SUBMITTED, FlowState.RESUBMIT_FAILED)),
                AttachmentCase.pwd_enc.is_not(None),
                AttachmentCase.resubmit_attempts < max_attempts)))

    def find_open_case_by_recipient(self, recipient: str) -> AttachmentCase | None:
        """Most-recent non-terminal case that lists this recipient (bounce-correlation
        fallback). A case may hold several recipients, so match by membership."""
        addr = (recipient or "").strip().lower()
        with self._sf() as s:
            rows = s.scalars(
                select(AttachmentCase)
                .where(AttachmentCase.state.not_in(TERMINAL))
                .order_by(AttachmentCase.updated_at.desc()))
            for case in rows:
                if addr in [r.strip().lower() for r in (case.recipient or "").split(",")]:
                    return case
            return None

    # --- read models for the dashboard/API ---------------------------------
    def list_cases(self, limit: int = 300) -> list[dict]:
        with self._sf() as s:
            cases = s.scalars(select(AttachmentCase).order_by(AttachmentCase.updated_at.desc()).limit(limit))
            return [_case_dict(c) for c in cases]

    def case_detail(self, case_id: str) -> dict | None:
        with self._sf() as s:
            case = s.get(AttachmentCase, case_id)
            if case is None:
                return None
            data = _case_dict(case)
            data["events"] = [
                {"state": e.state.value, "detail": e.detail, "at": e.created_at.isoformat()}
                for e in sorted(case.events, key=lambda e: e.created_at)
            ]
            return data


def _merge_recipients(existing: str | None, new: list[str]) -> str:
    """Union the stored comma-joined recipients with newly-seen ones, order preserved."""
    out, seen = [], set()
    for addr in [r.strip() for r in (existing or "").split(",")] + list(new):
        if addr and addr not in seen:
            seen.add(addr)
            out.append(addr)
    return ", ".join(out)


def _case_dict(c: AttachmentCase) -> dict:
    return {
        "id": c.id,
        "queue_id": c.queue_id,
        "recipient": c.recipient,
        "sender": c.sender,
        "subject": c.subject,
        "attachment": c.malware_name,
        "alert_name": c.alert_name,
        "state": c.state.value,
        "attempts": c.attempts,
        "notify_attempts": c.notify_attempts,
        "created_at": c.created_at.isoformat(),
        "updated_at": c.updated_at.isoformat(),
    }
