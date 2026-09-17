"""
Streamlit frontend for AI-Security-SOP-Compliance-POC.
Talks to the FastAPI backend over HTTP - no direct DB/LLM access from here.
Run via `streamlit run app.py`, or as the `frontend` service in docker-compose.
"""
import os
import pathlib

import requests
import streamlit as st

API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:8000")
API_KEY = os.environ.get("API_KEY", "")
AUTH_HEADERS = {"X-API-Key": API_KEY}
TEST_CASES_DIR = pathlib.Path(__file__).resolve().parent / "data" / "test_cases"
NONE_OPTION = "-- none --"

STATUS_COLOR = {"PASS": "green", "FAIL": "red", "WARN": "orange"}
STATUS_ICON = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️"}

st.set_page_config(page_title="SecureCode-AI", page_icon="🛡️", layout="wide")


@st.cache_data(ttl=5)
def load_demo_test_cases() -> dict[str, str]:
    """Read whatever is under data/test_cases/ so demo files show up automatically -
    no need to hardcode file names here."""
    cases = {}
    if TEST_CASES_DIR.exists():
        for path in sorted(TEST_CASES_DIR.rglob("*")):
            if path.is_file():
                label = str(path.relative_to(TEST_CASES_DIR)).replace("\\", "/")
                cases[label] = path.read_text()
    return cases


def _apply_demo_selection():
    selected = st.session_state.demo_select
    if selected != NONE_OPTION:
        st.session_state.code_text = st.session_state.demo_cases[selected]


st.title("🛡️ SecureCode-AI")
st.caption("AI-assisted code review against your organisation's Security SOP")

# --- Sidebar: SOP rule management -------------------------------------------------
with st.sidebar:
    st.header("SOP Rules")

    if st.button("🔄 (Re)load SOP rules into pgvector", use_container_width=True):
        with st.spinner("Ingesting rules..."):
            try:
                resp = requests.post(f"{API_BASE_URL}/sop/ingest", headers=AUTH_HEADERS, timeout=60)
                resp.raise_for_status()
                st.success(f"Loaded {resp.json()['ingested_rules']} rules")
            except Exception as exc:
                st.error(f"Ingest failed: {exc}")

    st.divider()

    try:
        rules_resp = requests.get(f"{API_BASE_URL}/sop/rules", headers=AUTH_HEADERS, timeout=10)
        rules_resp.raise_for_status()
        rules = rules_resp.json().get("rules", [])
        st.metric("Rules loaded", len(rules))
        with st.expander("View all rules"):
            for r in rules:
                st.markdown(f"**{r['rule_id']}** _{r['severity']}_ — {r['category']}")
    except Exception:
        st.warning("Could not reach the API. Is it running?")
        rules = []

    st.divider()
    st.caption(f"API: {API_BASE_URL}")

# --- Main: submit code for review -------------------------------------------------
if "code_text" not in st.session_state:
    st.session_state.code_text = ""
st.session_state.demo_cases = load_demo_test_cases()

col1, col2 = st.columns(2, gap="large")

with col1:
    st.subheader("Submit code for review")

    technology = st.selectbox(
        "Technology", ["fastapi", "nodejs", "nginx", "angular", "unspecified"]
    )

    demo_options = [NONE_OPTION] + list(st.session_state.demo_cases.keys())
    st.selectbox(
        "Load a demo test case",
        demo_options,
        key="demo_select",
        on_change=_apply_demo_selection,
        help="Loads one of the vulnerable/secure pairs from data/test_cases/",
    )

    uploaded = st.file_uploader("...or upload a file", type=["py", "js", "ts", "conf", "config"])
    if uploaded is not None:
        st.session_state.code_text = uploaded.read().decode("utf-8")

    st.text_area("Code to review", key="code_text", height=320)

    submit = st.button("🔍 Review Code", type="primary", use_container_width=True)

with col2:
    st.subheader("Assessment")

    if submit:
        code = st.session_state.code_text
        if not code.strip():
            st.warning("Paste or upload some code first.")
        else:
            with st.spinner("Analyzing against the SOP..."):
                try:
                    resp = requests.post(
                        f"{API_BASE_URL}/review",
                        json={"code": code, "technology": technology},
                        headers=AUTH_HEADERS,
                        timeout=120,
                    )
                    resp.raise_for_status()
                    st.session_state.last_result = resp.json()
                except Exception as exc:
                    st.error(f"Review request failed: {exc}")
                    st.session_state.last_result = None

    result = st.session_state.get("last_result")
    if result:
        assessment = result["assessment"]
        status = assessment["overall_status"]
        color = STATUS_COLOR.get(status, "gray")

        st.markdown(f"### Overall status: :{color}[{status}]")
        matched = result.get("retrieved_rule_ids") or []
        st.caption(f"Matched SOP rules considered: {', '.join(matched) if matched else 'none'}")

        findings = assessment.get("findings", [])
        if not findings:
            st.success("No violations found against the matched rules.")
        else:
            for f in findings:
                f_status = f.get("status", "WARN")
                icon = STATUS_ICON.get(f_status, "❔")
                title = f"{icon} {f.get('rule_id') or '—'} — {f.get('finding') or 'Finding'}"
                with st.expander(title, expanded=(f_status == "FAIL")):
                    c1, c2, c3 = st.columns(3)
                    c1.markdown(f"**Severity**\n\n{f.get('severity') or '—'}")
                    c2.markdown(f"**Confidence**\n\n{f.get('confidence') if f.get('confidence') is not None else '—'}")
                    c3.markdown(f"**Line**\n\n{f.get('line') or '—'}")
                    if f.get("reason"):
                        st.markdown(f"**Reason:** {f['reason']}")
                    if f.get("recommendation"):
                        st.info(f"💡 **Recommendation:** {f['recommendation']}")
    else:
        st.info("Submit code on the left to see the assessment here.")
