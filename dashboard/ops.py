"""VectorShield ops dashboard.

    streamlit run dashboard/ops.py

Reads the gateway's audit log directly and read-only. It does not call the
gateway's API and does not need the gateway to be running -- a security
dashboard that goes dark exactly when the service it watches goes down is
worse than no dashboard, because an operator learns to trust it.

Every number here comes from `dashboard/data.py`, which is tested. This file
is rendering and nothing else, so a chart cannot quietly disagree with the
query behind it.
"""

from __future__ import annotations

import sys
from pathlib import Path

# `streamlit run` puts this script's own directory first on sys.path, which is
# why this file is not called app.py: it would shadow the gateway's `app`
# package and `from app.config import ...` would resolve to this module. The
# repo root is prepended here as well so the dashboard runs from anywhere,
# not only from a shell whose working directory happens to be the project.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import streamlit as st
from sqlalchemy.orm import Session

from app.config import settings
from dashboard import data

REFRESH_SECONDS = 30

WINDOWS: dict[str, int | None] = {
    "Last hour": 1,
    "Last 24 hours": 24,
    "Last 7 days": 24 * 7,
    "Last 30 days": 24 * 30,
    "All time": None,
}

# Worst first, and coloured the way an operator expects to read them.
DECISION_COLORS = {
    "block": "#c0392b",
    "sanitize": "#d68910",
    "flag-and-log": "#b7950b",
    "allow": "#1e8449",
}

OWASP_LABELS = {
    "LLM01": "LLM01 · Prompt injection",
    "LLM04": "LLM04 · Model denial of service",
    "LLM06": "LLM06 · Sensitive information disclosure",
    "LLM10": "LLM10 · Model theft / extraction",
}

st.set_page_config(page_title="VectorShield", page_icon="🛡️", layout="wide")


@st.cache_resource
def _engine():
    """One engine for the process. Cached so a rerun does not reopen the file."""
    return data.get_engine(settings.database_url)


def _session() -> Session:
    return Session(_engine())


def _fmt_pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _fmt_int(value: int) -> str:
    return f"{value:,}"


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------

st.sidebar.title("🛡️ VectorShield")
st.sidebar.caption("Ops dashboard")

window_label = st.sidebar.selectbox("Time window", list(WINDOWS), index=1)
hours = WINDOWS[window_label]

with _session() as session:
    tenants = data.tenant_summary(session, hours=hours)

tenant_choices = {"All tenants": None} | {
    f"{t['name']} ({t['requests']:,} req)": t["tenant_id"] for t in tenants
}
tenant_label = st.sidebar.selectbox("Tenant", list(tenant_choices))
tenant_id = tenant_choices[tenant_label]

if st.sidebar.button("Refresh now", width="stretch"):
    st.cache_data.clear()
    st.rerun()

st.sidebar.divider()
st.sidebar.caption(
    f"Reading `{data.sync_url(settings.database_url)}` read-only.\n\n"
    "The gateway does not need to be running."
)


# --------------------------------------------------------------------------
# Data loading
# --------------------------------------------------------------------------


@st.cache_data(ttl=REFRESH_SECONDS, show_spinner=False)
def load(hours: int | None, tenant_id: str | None) -> dict:
    """Everything the page needs, in one pass.

    Cached briefly so the six panels below share a single consistent read
    instead of each issuing its own and disagreeing with the others.
    """
    with _session() as session:
        return {
            "overview": data.overview(session, hours=hours, tenant_id=tenant_id).as_dict(),
            "series": data.decisions_over_time(
                session,
                hours=hours,
                tenant_id=tenant_id,
                bucket="minute" if hours == 1 else "hour" if (hours or 999) <= 168 else "day",
            ),
            "detectors": data.findings_by_detector(session, hours=hours, tenant_id=tenant_id),
            "categories": data.findings_by_category(session, hours=hours, tenant_id=tenant_id),
            "latency": data.latency_breakdown(session, hours=hours, tenant_id=tenant_id),
            "tenants": data.tenant_summary(session, hours=hours),
        }


state = load(hours, tenant_id)
ov = state["overview"]

st.title("Security overview")
st.caption(f"{window_label.lower()} · {tenant_label}")

if not ov["requests"]:
    st.info(
        "No requests logged in this window yet. Send one through the gateway "
        "and it will appear here.",
        icon="📭",
    )
    st.stop()


# --------------------------------------------------------------------------
# Headline numbers
# --------------------------------------------------------------------------

cols = st.columns(5)
cols[0].metric("Requests", _fmt_int(ov["requests"]))
cols[1].metric("Blocked", _fmt_int(ov["blocked"]), help="Refused before reaching the model")
cols[2].metric(
    "Answers redacted",
    _fmt_int(ov["sanitized"]),
    help="A leak was cut out of the response and the rest delivered",
)
cols[3].metric(
    "Intervention rate",
    _fmt_pct(ov["intervention_rate"]),
    help="Share of traffic the gateway blocked, redacted, or flagged",
)
cols[4].metric(
    "Gateway overhead (p95)",
    f"{ov['p95_overhead_ms']:.2f} ms",
    help="Inspection cost, excluding the upstream model call",
)

if ov["upstream_errors"]:
    st.warning(
        f"{ov['upstream_errors']:,} request(s) failed upstream in this window. "
        "That is the model provider, not the gateway.",
        icon="⚠️",
    )

st.divider()


# --------------------------------------------------------------------------
# Traffic over time
# --------------------------------------------------------------------------

left, right = st.columns([3, 2])

with left:
    st.subheader("Decisions over time")
    frame = pd.DataFrame(state["series"])
    if frame.empty:
        st.caption("Nothing to plot in this window.")
    else:
        frame["bucket"] = pd.to_datetime(frame["bucket"])
        present = [d for d in data.DECISIONS if d in frame.columns]
        st.bar_chart(
            frame.set_index("bucket")[present],
            color=[DECISION_COLORS[d] for d in present],
            height=320,
        )

with right:
    st.subheader("OWASP categories hit")
    categories = state["categories"]
    if not categories:
        st.caption("No detector fired in this window.")
    else:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Category": OWASP_LABELS.get(c["category"], c["category"]),
                        "Findings": c["hits"],
                    }
                    for c in categories
                ]
            ),
            hide_index=True,
            width="stretch",
        )
        st.caption(
            "A category with no findings is not necessarily quiet traffic -- it "
            "may simply be a threat this corpus never contained."
        )


# --------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------

st.subheader("Which detectors are firing")
detectors = state["detectors"]
if not detectors:
    st.caption("No findings in this window.")
else:
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Detector": d["detector"],
                    "OWASP": d["category"],
                    "Direction": d["direction"],
                    "Hits": d["hits"],
                    "Avg confidence": d["avg_confidence"],
                }
                for d in detectors
            ]
        ),
        hide_index=True,
        width="stretch",
    )
    st.caption(
        "A detector with many hits at low average confidence is a tuning "
        "problem, not a finding: it is filling the audit log without ever "
        "being certain enough to act."
    )


# --------------------------------------------------------------------------
# Latency
# --------------------------------------------------------------------------

st.subheader("What the gateway costs")
lat = state["latency"]
lcols = st.columns(4)
lcols[0].metric("Overhead (median)", f"{lat['overhead_median_ms']:.2f} ms")
lcols[1].metric("Overhead (p95)", f"{lat['overhead_p95_ms']:.2f} ms")
lcols[2].metric("Overhead (p99)", f"{lat['overhead_p99_ms']:.2f} ms")
lcols[3].metric(
    "Share of request time",
    _fmt_pct(lat["overhead_share"]),
    help="Gateway inspection as a fraction of total time, including the model call",
)
st.caption(
    f"Measured over {lat['n']:,} logged requests in this window, against an "
    f"upstream median of {lat['upstream_median_ms']:.0f} ms. These are real "
    "numbers from this deployment, not the benchmark's."
)

st.divider()


# --------------------------------------------------------------------------
# Triage queue
# --------------------------------------------------------------------------

st.subheader("Triage queue")
only_interesting = st.checkbox(
    "Only requests the gateway acted on", value=True, help="Blocked or flagged"
)
limit = st.slider("Rows", min_value=25, max_value=500, value=100, step=25)

with _session() as session:
    rows = data.recent_requests(
        session,
        hours=hours,
        tenant_id=tenant_id,
        limit=limit,
        decisions=("block", "flag-and-log") if only_interesting else None,
    )

if not rows:
    st.success("Nothing to triage in this window.", icon="✅")
else:
    table = pd.DataFrame(
        [
            {
                "When": r["created_at"],
                "Decision": r["decision"],
                "Risk": r["risk_score"],
                "Outbound": r["outbound_decision"] or "—",
                "Reason": r["blocked_by"] or "—",
                "Model": r["model"],
                "Tokens": r["prompt_tokens"] + r["completion_tokens"],
                "Overhead": f"{r['overhead_ms']:.2f} ms",
                "id": r["id"],
            }
            for r in rows
        ]
    )
    st.dataframe(table, hide_index=True, width="stretch")

    chosen = st.selectbox(
        "Inspect a request",
        options=[r["id"] for r in rows],
        format_func=lambda rid: f"{rid[:12]}…",
    )
    if chosen:
        with _session() as session:
            findings = data.request_findings(session, chosen)
        record = next(r for r in rows if r["id"] == chosen)

        st.markdown(
            f"**Request `{chosen}`** · {record['decision']} · risk {record['risk_score']}"
        )
        if findings:
            st.dataframe(pd.DataFrame(findings), hide_index=True, width="stretch")
        else:
            st.caption("No findings recorded for this request.")

        if record["prompt_text"]:
            with st.expander("Prompt text"):
                st.code(record["prompt_text"])
        else:
            st.caption(
                "Prompt text was not retained. Content is hashed by default; "
                "set STORE_CONTENT=true, or a tenant's own override, to keep it. "
                "Blocked and sanitized requests always retain it."
            )


# --------------------------------------------------------------------------
# Tenants
# --------------------------------------------------------------------------

st.divider()
st.subheader("Tenants")
st.dataframe(
    pd.DataFrame(
        [
            {
                "Tenant": t["name"],
                "Active": t["active"],
                "Requests": t["requests"],
                "Blocked": t["blocked"],
                "Redacted": t["sanitized"],
                "Flagged": t["flagged"],
                "Intervention rate": _fmt_pct(t["intervention_rate"]),
                "Tokens": t["prompt_tokens"] + t["completion_tokens"],
            }
            for t in state["tenants"]
        ]
    ),
    hide_index=True,
    width="stretch",
)
