"""Query layer for the ops dashboard.

Deliberately separate from the Streamlit app, for two reasons. It is the half
worth testing -- a wrong aggregate is a wrong decision by an operator -- and
tests should not have to import Streamlit to check a GROUP BY. Every function
here returns plain Python, so the UI layer is a rendering concern and nothing
else.

Reads are synchronous and read-only. The dashboard is a separate process from
the gateway and must never be able to write to or lock the audit log: it opens
its own connection, runs aggregates, and closes. It can point at a production
replica with a read-only credential and nothing here will mind.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, create_engine, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.db.models import FindingLog, RequestLog, Tenant

# Decisions in the order an operator reads them: worst first.
DECISIONS = ("block", "sanitize", "flag-and-log", "allow")


def sync_url(database_url: str) -> str:
    """Turn the gateway's async URL into the sync one this process needs.

    The gateway runs on aiosqlite/asyncpg; a Streamlit script has no event
    loop worth feeding, so the same configured URL is reused with a sync
    driver rather than making the operator configure the database twice and
    risk pointing the dashboard at a different one.
    """
    for async_driver, sync_driver in (
        ("sqlite+aiosqlite://", "sqlite://"),
        ("postgresql+asyncpg://", "postgresql+psycopg://"),
        ("postgres://", "postgresql+psycopg://"),
    ):
        if database_url.startswith(async_driver):
            return database_url.replace(async_driver, sync_driver, 1)
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    return database_url


def get_engine(database_url: str) -> Engine:
    return create_engine(sync_url(database_url), future=True)


@dataclass(slots=True)
class Overview:
    """The numbers an operator checks first."""

    requests: int = 0
    blocked: int = 0
    sanitized: int = 0
    flagged: int = 0
    allowed: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    median_overhead_ms: float = 0.0
    p95_overhead_ms: float = 0.0
    upstream_errors: int = 0

    @property
    def block_rate(self) -> float:
        return self.blocked / self.requests if self.requests else 0.0

    @property
    def intervention_rate(self) -> float:
        """Share of traffic the gateway did something about.

        Blocked plus sanitized plus flagged: everything that was not passed
        through silently. This is the number that tells an operator whether
        their thresholds are sane, and the one that moves when they are not.
        """
        if not self.requests:
            return 0.0
        return (self.blocked + self.sanitized + self.flagged) / self.requests

    def as_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "block_rate": round(self.block_rate, 4),
            "intervention_rate": round(self.intervention_rate, 4),
        }


def _window(hours: int | None) -> datetime | None:
    if hours is None:
        return None
    return datetime.now(UTC) - timedelta(hours=hours)


def _scoped(stmt, since: datetime | None, tenant_id: str | None):
    if since is not None:
        stmt = stmt.where(RequestLog.created_at >= since)
    if tenant_id:
        stmt = stmt.where(RequestLog.tenant_id == tenant_id)
    return stmt


def _percentile(values: list[float], fraction: float) -> float:
    """Nearest-rank percentile.

    Computed in Python rather than SQL on purpose: SQLite has no percentile
    function, and an operator running the dashboard against the default SQLite
    file should see the same numbers as one running Postgres.
    """
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return round(ordered[index], 3)


def overview(
    session: Session, *, hours: int | None = 24, tenant_id: str | None = None
) -> Overview:
    since = _window(hours)

    counted = {
        d: func.sum(case((RequestLog.decision == d, 1), else_=0)).label(d)
        for d in ("block", "flag-and-log", "allow")
    }
    stmt = _scoped(
        select(
            func.count(RequestLog.id),
            func.coalesce(func.sum(RequestLog.prompt_tokens), 0),
            func.coalesce(func.sum(RequestLog.completion_tokens), 0),
            counted["block"],
            counted["flag-and-log"],
            counted["allow"],
            # A sanitize is recorded on the outbound verdict, not the inbound
            # decision: the request was allowed in and the *answer* was
            # rewritten on the way out.
            func.sum(case((RequestLog.outbound_decision == "sanitize", 1), else_=0)),
            func.sum(case((RequestLog.status_code >= 500, 1), else_=0)),
        ),
        since,
        tenant_id,
    )
    row = session.execute(stmt).one()

    overheads = session.execute(
        _scoped(select(RequestLog.overhead_ms), since, tenant_id)
    ).scalars()
    values = [float(v) for v in overheads if v is not None]

    return Overview(
        requests=int(row[0] or 0),
        prompt_tokens=int(row[1] or 0),
        completion_tokens=int(row[2] or 0),
        blocked=int(row[3] or 0),
        flagged=int(row[4] or 0),
        allowed=int(row[5] or 0),
        sanitized=int(row[6] or 0),
        upstream_errors=int(row[7] or 0),
        median_overhead_ms=_percentile(values, 0.5),
        p95_overhead_ms=_percentile(values, 0.95),
    )


def decisions_over_time(
    session: Session,
    *,
    hours: int | None = 24,
    tenant_id: str | None = None,
    bucket: str = "hour",
) -> list[dict[str, Any]]:
    """Request counts per decision, bucketed for a stacked chart.

    Bucketing is done in Python. The alternative is date_trunc, which Postgres
    has and SQLite does not, and a dashboard that only works on one of the two
    databases the project supports is not finished.
    """
    since = _window(hours)
    rows = session.execute(
        _scoped(
            select(RequestLog.created_at, RequestLog.decision, RequestLog.outbound_decision),
            since,
            tenant_id,
        )
    ).all()

    truncate = {
        "minute": lambda d: d.replace(second=0, microsecond=0),
        "hour": lambda d: d.replace(minute=0, second=0, microsecond=0),
        "day": lambda d: d.replace(hour=0, minute=0, second=0, microsecond=0),
    }[bucket]

    buckets: dict[datetime, dict[str, int]] = {}
    for created_at, decision, outbound in rows:
        if created_at is None:
            continue
        key = truncate(created_at)
        slot = buckets.setdefault(key, dict.fromkeys(DECISIONS, 0))
        # An answer that was rewritten on the way out is reported as a
        # sanitize, even though the request itself was allowed in: that is
        # what the operator needs to see.
        slot["sanitize" if outbound == "sanitize" else decision] = (
            slot.get("sanitize" if outbound == "sanitize" else decision, 0) + 1
        )

    return [{"bucket": key.isoformat(), **counts} for key, counts in sorted(buckets.items())]


def findings_by_detector(
    session: Session, *, hours: int | None = 24, tenant_id: str | None = None
) -> list[dict[str, Any]]:
    """Which detectors are firing, and how confidently."""
    since = _window(hours)
    stmt = (
        select(
            FindingLog.detector,
            FindingLog.category,
            FindingLog.direction,
            func.count(FindingLog.id).label("hits"),
            func.avg(FindingLog.confidence).label("avg_confidence"),
        )
        .join(RequestLog, RequestLog.id == FindingLog.request_id)
        .group_by(FindingLog.detector, FindingLog.category, FindingLog.direction)
        .order_by(func.count(FindingLog.id).desc())
    )
    rows = session.execute(_scoped(stmt, since, tenant_id)).all()
    return [
        {
            "detector": r.detector,
            "category": r.category,
            "direction": r.direction,
            "hits": int(r.hits),
            "avg_confidence": round(float(r.avg_confidence or 0.0), 3),
        }
        for r in rows
    ]


def findings_by_category(
    session: Session, *, hours: int | None = 24, tenant_id: str | None = None
) -> list[dict[str, Any]]:
    """OWASP coverage in practice: which categories this traffic actually hit."""
    since = _window(hours)
    stmt = (
        select(FindingLog.category, func.count(FindingLog.id).label("hits"))
        .join(RequestLog, RequestLog.id == FindingLog.request_id)
        .group_by(FindingLog.category)
        .order_by(FindingLog.category)
    )
    rows = session.execute(_scoped(stmt, since, tenant_id)).all()
    return [{"category": r.category, "hits": int(r.hits)} for r in rows]


def recent_requests(
    session: Session,
    *,
    hours: int | None = 24,
    tenant_id: str | None = None,
    limit: int = 100,
    decisions: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    """The triage queue: most recent requests, worst first within a timestamp."""
    since = _window(hours)
    stmt = select(RequestLog).order_by(RequestLog.created_at.desc()).limit(limit)
    if decisions:
        stmt = stmt.where(RequestLog.decision.in_(decisions))
    rows = session.execute(_scoped(stmt, since, tenant_id)).scalars().all()
    return [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "tenant_id": r.tenant_id,
            "route": r.route,
            "provider": r.provider,
            "model": r.model,
            "decision": r.decision,
            "risk_score": round(float(r.risk_score or 0.0), 4),
            "outbound_decision": r.outbound_decision,
            "outbound_risk_score": (
                round(float(r.outbound_risk_score), 4)
                if r.outbound_risk_score is not None
                else None
            ),
            "blocked_by": r.blocked_by,
            "status_code": r.status_code,
            "prompt_tokens": r.prompt_tokens,
            "completion_tokens": r.completion_tokens,
            "overhead_ms": round(float(r.overhead_ms or 0.0), 3),
            # Present only when the tenant opted into retention or the request
            # was blocked. Absent is the normal case, and the UI says so
            # rather than rendering an empty column as though nothing happened.
            "prompt_text": r.prompt_text,
        }
        for r in rows
    ]


def request_findings(session: Session, request_id: str) -> list[dict[str, Any]]:
    """Every finding attached to one request, for the detail view."""
    rows = (
        session.execute(
            select(FindingLog)
            .where(FindingLog.request_id == request_id)
            .order_by(FindingLog.confidence.desc())
        )
        .scalars()
        .all()
    )
    return [
        {
            "detector": f.detector,
            "category": f.category,
            "severity": f.severity,
            "direction": f.direction,
            "confidence": round(float(f.confidence or 0.0), 3),
            "message": f.message,
            "evidence": f.evidence,
        }
        for f in rows
    ]


def tenant_summary(session: Session, *, hours: int | None = 24) -> list[dict[str, Any]]:
    """Per-tenant traffic and intervention rates.

    Tenants with no traffic in the window are still listed: "this key sent
    nothing today" is information, and a tenant that vanishes from the table
    looks like it was deleted.
    """
    since = _window(hours)
    counts = select(
        RequestLog.tenant_id,
        func.count(RequestLog.id).label("requests"),
        func.sum(case((RequestLog.decision == "block", 1), else_=0)).label("blocked"),
        func.sum(case((RequestLog.outbound_decision == "sanitize", 1), else_=0)).label(
            "sanitized"
        ),
        func.sum(case((RequestLog.decision == "flag-and-log", 1), else_=0)).label("flagged"),
        func.coalesce(func.sum(RequestLog.prompt_tokens), 0).label("prompt_tokens"),
        func.coalesce(func.sum(RequestLog.completion_tokens), 0).label("completion_tokens"),
    ).group_by(RequestLog.tenant_id)
    if since is not None:
        counts = counts.where(RequestLog.created_at >= since)
    by_tenant = {r.tenant_id: r for r in session.execute(counts).all()}

    tenants = session.execute(select(Tenant).order_by(Tenant.created_at)).scalars().all()
    out: list[dict[str, Any]] = []
    for tenant in tenants:
        row = by_tenant.get(tenant.id)
        requests = int(row.requests) if row else 0
        blocked = int(row.blocked or 0) if row else 0
        sanitized = int(row.sanitized or 0) if row else 0
        flagged = int(row.flagged or 0) if row else 0
        out.append(
            {
                "tenant_id": tenant.id,
                "name": tenant.name,
                "active": tenant.active,
                "requests": requests,
                "blocked": blocked,
                "sanitized": sanitized,
                "flagged": flagged,
                "prompt_tokens": int(row.prompt_tokens) if row else 0,
                "completion_tokens": int(row.completion_tokens) if row else 0,
                "intervention_rate": (
                    round((blocked + sanitized + flagged) / requests, 4) if requests else 0.0
                ),
            }
        )
    return sorted(out, key=lambda t: t["requests"], reverse=True)


def latency_breakdown(
    session: Session, *, hours: int | None = 24, tenant_id: str | None = None
) -> dict[str, float]:
    """Gateway overhead against upstream time -- the "what does this cost me"
    question, answered from real traffic rather than the benchmark."""
    since = _window(hours)
    rows = session.execute(
        _scoped(
            select(RequestLog.overhead_ms, RequestLog.upstream_latency_ms), since, tenant_id
        )
    ).all()
    overhead = [float(o) for o, _ in rows if o is not None]
    upstream = [float(u) for _, u in rows if u is not None]
    total = (sum(overhead) + sum(upstream)) or 0.0
    return {
        "n": len(rows),
        "overhead_median_ms": _percentile(overhead, 0.5),
        "overhead_p95_ms": _percentile(overhead, 0.95),
        "overhead_p99_ms": _percentile(overhead, 0.99),
        "upstream_median_ms": _percentile(upstream, 0.5),
        "overhead_share": round(sum(overhead) / total, 5) if total else 0.0,
    }
