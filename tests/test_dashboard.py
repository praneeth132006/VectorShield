"""Dashboard query layer.

Aggregates are worth testing because a wrong one is a wrong decision by an
operator. These run against a real SQLite database with hand-placed rows, so
the SQL is actually exercised rather than mocked.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.models import Base, FindingLog, RequestLog, Tenant
from dashboard import data


@pytest.fixture
def session(tmp_path) -> Session:
    engine = create_engine(f"sqlite:///{tmp_path / 'dash.db'}", future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _tenant(session: Session, name: str = "acme", tid: str = "t1") -> Tenant:
    tenant = Tenant(id=tid, name=name, api_key_hash=f"hash-{tid}", api_key_prefix="vs_test")
    session.add(tenant)
    session.commit()
    return tenant


def _request(
    session: Session,
    *,
    tenant_id: str = "t1",
    decision: str = "allow",
    outbound: str | None = None,
    risk: float = 0.0,
    minutes_ago: int = 1,
    at: datetime | None = None,
    overhead: float = 1.0,
    upstream: float | None = 500.0,
    prompt_tokens: int = 10,
    completion_tokens: int = 20,
    status_code: int = 200,
    findings: list[tuple[str, str, float]] | None = None,
) -> RequestLog:
    row = RequestLog(
        tenant_id=tenant_id,
        created_at=at or (datetime.now(UTC) - timedelta(minutes=minutes_ago)),
        provider="mock",
        model="mock-model",
        prompt_hash="x" * 64,
        decision=decision,
        risk_score=risk,
        outbound_decision=outbound,
        outbound_risk_score=0.9 if outbound else None,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        overhead_ms=overhead,
        upstream_latency_ms=upstream,
        status_code=status_code,
    )
    session.add(row)
    session.flush()
    for detector, category, confidence in findings or []:
        session.add(
            FindingLog(
                request_id=row.id,
                detector=detector,
                category=category,
                severity="high",
                direction="inbound",
                confidence=confidence,
                message=f"{detector} fired",
            )
        )
    session.commit()
    return row


# --------------------------------------------------------------------------
# URL translation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        ("sqlite+aiosqlite:///./vectorshield.db", "sqlite:///./vectorshield.db"),
        ("postgresql+asyncpg://u:p@h/db", "postgresql+psycopg://u:p@h/db"),
        ("postgresql://u:p@h/db", "postgresql+psycopg://u:p@h/db"),
        ("postgres://u:p@h/db", "postgresql+psycopg://u:p@h/db"),
        ("sqlite:///already-sync.db", "sqlite:///already-sync.db"),
    ],
)
def test_async_urls_become_sync(configured: str, expected: str):
    """The dashboard reuses the gateway's configured URL.

    Making the operator configure the database twice invites pointing the
    dashboard at a different one than the gateway writes to.
    """
    assert data.sync_url(configured) == expected


# --------------------------------------------------------------------------
# Overview
# --------------------------------------------------------------------------


def test_overview_on_an_empty_database(session: Session):
    """A fresh install must render, not divide by zero."""
    result = data.overview(session)
    assert result.requests == 0
    assert result.block_rate == 0.0
    assert result.intervention_rate == 0.0
    assert result.as_dict()["block_rate"] == 0.0


def test_overview_counts_decisions(session: Session):
    _tenant(session)
    _request(session, decision="allow")
    _request(session, decision="allow")
    _request(session, decision="block", risk=0.95)
    _request(session, decision="flag-and-log", risk=0.6)

    result = data.overview(session)
    assert result.requests == 4
    assert result.allowed == 2
    assert result.blocked == 1
    assert result.flagged == 1
    assert result.block_rate == pytest.approx(0.25)


def test_a_sanitized_answer_is_counted_as_an_intervention(session: Session):
    """The request was allowed in; the *answer* was rewritten on the way out.

    Reading only the inbound decision would report this as untouched traffic.
    """
    _tenant(session)
    _request(session, decision="allow", outbound="sanitize")
    result = data.overview(session)
    assert result.sanitized == 1
    assert result.allowed == 1
    assert result.intervention_rate == pytest.approx(1.0)


def test_overview_sums_tokens(session: Session):
    _tenant(session)
    _request(session, prompt_tokens=100, completion_tokens=50)
    _request(session, prompt_tokens=10, completion_tokens=5)
    result = data.overview(session)
    assert result.prompt_tokens == 110
    assert result.completion_tokens == 55


def test_overview_reports_overhead_percentiles(session: Session):
    _tenant(session)
    for ms in (1.0, 2.0, 3.0, 50.0):
        _request(session, overhead=ms)
    result = data.overview(session)
    assert 1.0 <= result.median_overhead_ms <= 3.0
    assert result.p95_overhead_ms == 50.0


def test_overview_respects_the_time_window(session: Session):
    _tenant(session)
    _request(session, minutes_ago=5)
    _request(session, minutes_ago=60 * 48)  # two days old
    assert data.overview(session, hours=24).requests == 1
    assert data.overview(session, hours=None).requests == 2


def test_overview_can_be_scoped_to_one_tenant(session: Session):
    _tenant(session, "acme", "t1")
    _tenant(session, "other", "t2")
    _request(session, tenant_id="t1")
    _request(session, tenant_id="t2")
    _request(session, tenant_id="t2")
    assert data.overview(session, tenant_id="t2").requests == 2


def test_overview_counts_upstream_errors(session: Session):
    _tenant(session)
    _request(session, status_code=200)
    _request(session, status_code=502)
    assert data.overview(session).upstream_errors == 1


# --------------------------------------------------------------------------
# Time series
# --------------------------------------------------------------------------


def test_decisions_over_time_buckets_by_hour(session: Session):
    """Two requests in one hour collapse into one bucket; a third hours away
    does not.

    Explicit timestamps rather than "minutes ago": two requests five minutes
    apart land in different hours whenever the clock happens to sit near the
    boundary, which made an earlier version of this test fail at :57.
    """
    _tenant(session)
    now = datetime.now(UTC).replace(minute=30, second=0, microsecond=0)
    _request(session, at=now, decision="allow")
    _request(session, at=now - timedelta(minutes=10), decision="block")
    _request(session, at=now - timedelta(hours=3), decision="allow")

    series = data.decisions_over_time(session, hours=24, bucket="hour")
    assert len(series) == 2
    assert sum(row["allow"] + row["block"] for row in series) == 3
    # The bucket label's timezone suffix differs by backend -- SQLite hands
    # back naive datetimes where Postgres keeps the offset -- so the hour is
    # compared rather than the exact string.
    latest = series[-1]
    assert latest["bucket"].startswith(now.replace(minute=0).strftime("%Y-%m-%dT%H:00:00"))
    assert {k: v for k, v in latest.items() if k != "bucket"} == {
        "block": 1,
        "sanitize": 0,
        "flag-and-log": 0,
        "allow": 1,
    }


def test_time_series_is_chronological(session: Session):
    _tenant(session)
    for minutes in (180, 5, 90):
        _request(session, minutes_ago=minutes)
    series = data.decisions_over_time(session)
    assert [r["bucket"] for r in series] == sorted(r["bucket"] for r in series)


def test_time_series_is_empty_without_traffic(session: Session):
    assert data.decisions_over_time(session) == []


def test_sanitized_answers_appear_in_the_series(session: Session):
    _tenant(session)
    _request(session, decision="allow", outbound="sanitize")
    series = data.decisions_over_time(session)
    assert series[0]["sanitize"] == 1


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


def test_findings_are_grouped_by_detector(session: Session):
    _tenant(session)
    _request(session, findings=[("rules", "LLM01", 0.9), ("secrets", "LLM06", 0.8)])
    _request(session, findings=[("rules", "LLM01", 0.7)])

    rows = data.findings_by_detector(session)
    by_name = {r["detector"]: r for r in rows}
    assert by_name["rules"]["hits"] == 2
    assert by_name["rules"]["avg_confidence"] == pytest.approx(0.8)
    assert by_name["secrets"]["hits"] == 1


def test_findings_are_ordered_by_volume(session: Session):
    _tenant(session)
    for _ in range(3):
        _request(session, findings=[("rules", "LLM01", 0.9)])
    _request(session, findings=[("secrets", "LLM06", 0.9)])
    assert data.findings_by_detector(session)[0]["detector"] == "rules"


def test_findings_by_category_shows_owasp_coverage(session: Session):
    _tenant(session)
    _request(
        session,
        findings=[
            ("rules", "LLM01", 0.9),
            ("resource-abuse", "LLM04", 0.6),
            ("extraction", "LLM10", 0.5),
        ],
    )
    categories = {r["category"]: r["hits"] for r in data.findings_by_category(session)}
    assert categories == {"LLM01": 1, "LLM04": 1, "LLM10": 1}


def test_findings_respect_the_time_window(session: Session):
    _tenant(session)
    _request(session, minutes_ago=60 * 48, findings=[("rules", "LLM01", 0.9)])
    assert data.findings_by_detector(session, hours=24) == []


# --------------------------------------------------------------------------
# Triage queue
# --------------------------------------------------------------------------


def test_recent_requests_are_newest_first(session: Session):
    _tenant(session)
    _request(session, minutes_ago=30, risk=0.1)
    _request(session, minutes_ago=1, risk=0.9)
    rows = data.recent_requests(session)
    assert rows[0]["risk_score"] == 0.9


def test_recent_requests_can_be_filtered_to_blocks(session: Session):
    _tenant(session)
    _request(session, decision="allow")
    _request(session, decision="block")
    rows = data.recent_requests(session, decisions=("block",))
    assert len(rows) == 1
    assert rows[0]["decision"] == "block"


def test_recent_requests_honours_the_limit(session: Session):
    _tenant(session)
    for _ in range(10):
        _request(session)
    assert len(data.recent_requests(session, limit=3)) == 3


def test_prompt_text_is_absent_unless_retained(session: Session):
    """Hashed-by-default means the column is usually empty, and that is correct."""
    _tenant(session)
    _request(session)
    assert data.recent_requests(session)[0]["prompt_text"] is None


def test_request_findings_detail_is_ordered_by_confidence(session: Session):
    _tenant(session)
    row = _request(session, findings=[("weak", "LLM06", 0.3), ("strong", "LLM01", 0.95)])
    findings = data.request_findings(session, row.id)
    assert [f["detector"] for f in findings] == ["strong", "weak"]


def test_request_findings_for_an_unknown_id_is_empty(session: Session):
    assert data.request_findings(session, "does-not-exist") == []


# --------------------------------------------------------------------------
# Per-tenant
# --------------------------------------------------------------------------


def test_tenant_summary_reports_intervention_rate(session: Session):
    _tenant(session, "acme", "t1")
    _request(session, tenant_id="t1", decision="allow")
    _request(session, tenant_id="t1", decision="block")
    summary = data.tenant_summary(session)
    assert summary[0]["requests"] == 2
    assert summary[0]["intervention_rate"] == pytest.approx(0.5)


def test_a_silent_tenant_is_still_listed(session: Session):
    """ "This key sent nothing today" is information, not a reason to vanish."""
    _tenant(session, "quiet", "t9")
    summary = data.tenant_summary(session)
    assert len(summary) == 1
    assert summary[0]["requests"] == 0
    assert summary[0]["intervention_rate"] == 0.0


def test_tenant_summary_is_busiest_first(session: Session):
    _tenant(session, "quiet", "t1")
    _tenant(session, "busy", "t2")
    _request(session, tenant_id="t1")
    for _ in range(5):
        _request(session, tenant_id="t2")
    assert [t["name"] for t in data.tenant_summary(session)] == ["busy", "quiet"]


# --------------------------------------------------------------------------
# Latency
# --------------------------------------------------------------------------


def test_latency_breakdown_reports_the_overhead_share(session: Session):
    _tenant(session)
    for _ in range(10):
        _request(session, overhead=1.0, upstream=999.0)
    breakdown = data.latency_breakdown(session)
    assert breakdown["overhead_median_ms"] == 1.0
    assert breakdown["upstream_median_ms"] == 999.0
    assert breakdown["overhead_share"] < 0.01


def test_latency_breakdown_on_an_empty_database(session: Session):
    breakdown = data.latency_breakdown(session)
    assert breakdown["n"] == 0
    assert breakdown["overhead_share"] == 0.0


def test_latency_ignores_requests_with_no_upstream_call(session: Session):
    """A blocked request never reached the model; it has no upstream time."""
    _tenant(session)
    _request(session, decision="block", upstream=None, overhead=2.0)
    breakdown = data.latency_breakdown(session)
    assert breakdown["overhead_median_ms"] == 2.0
    assert breakdown["upstream_median_ms"] == 0.0


def test_percentile_helper_handles_one_value():
    assert data._percentile([5.0], 0.95) == 5.0
    assert data._percentile([], 0.5) == 0.0
