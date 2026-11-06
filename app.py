"""SysAdmin Guard-AI - Streamlit portal."""
import pandas as pd
import streamlit as st

from engine import InferenceEngine
from report import build_pdf
from rules import RULES
from schema import DEFAULTS, FIELDS, GROUPS, PRESETS

st.set_page_config(page_title="SysAdmin Guard-AI", page_icon="🛡️", layout="wide")
ENGINE = InferenceEngine(RULES)
BADGE = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


def load_preset():
    for k, v in {**DEFAULTS, **PRESETS[st.session_state["preset"]]}.items():
        st.session_state[k] = v


if "init" not in st.session_state:
    st.session_state["preset"] = list(PRESETS)[0]
    load_preset()
    st.session_state["init"] = True


def widget(field, col):
    key, label, kind, _, arg, _ = field
    if kind == "bool":
        col.toggle(label, key=key)
    elif kind == "int":
        col.slider(label, arg[0], arg[1], key=key)
    elif kind == "float":
        col.slider(label, arg[0], arg[1], step=0.1, key=key)
    else:
        col.selectbox(label, arg, key=key)


with st.sidebar:
    st.header("🛡️ SysAdmin Guard-AI")
    st.text_input("Hostname", "prod-web-01", key="host")
    st.selectbox("Load sample profile", list(PRESETS), key="preset", on_change=load_preset)
    st.caption(f"{len(RULES)} rules · deterministic forward chaining")

st.title("🛡️ SysAdmin Guard-AI")
st.caption("Linux/Unix server health, security hardening & compliance expert system "
           "(CIS · SOC 2). Change any input and the inference engine re-runs instantly.")

tab_cfg, tab_dash, tab_trail, tab_rules = st.tabs(
    ["🖥️ Server configuration", "📊 Risk dashboard", "🔗 Audit trail", "📚 Rule base"])

with tab_cfg:
    for g in GROUPS:
        with st.expander(g, expanded=g in ("Network", "Authentication")):
            cols = st.columns(3)
            for n, f in enumerate([f for f in FIELDS if f[5] == g]):
                widget(f, cols[n % 3])

facts = {f[0]: st.session_state[f[0]] for f in FIELDS}
res = ENGINE.run(facts)

with st.sidebar:
    st.download_button("📄 Download PDF report", build_pdf(st.session_state["host"], res),
                       file_name=f"{st.session_state['host']}_guard_ai_report.pdf",
                       mime="application/pdf")

with tab_dash:
    c = st.columns(4)
    c[0].metric("Risk score", f"{res.risk}/100")
    c[1].metric("Rating", res.rating)
    c[2].metric("Findings", len(res.findings))
    c[3].metric("Rules fired", f"{len(res.fired)}/{len(RULES)}")
    st.progress(float(res.risk) / 100)

    st.subheader("Framework compliance")
    cc = st.columns(2)
    for col, (fw, d) in zip(cc, res.compliance().items()):
        col.metric(f"{fw} pass rate", f"{d['pct']}%",
                   f"{d['status']} · {d['failed']}/{d['checks']} checks failed", delta_color="off")

    if res.by_category:
        st.subheader("Risk points by category")
        st.bar_chart(pd.Series(res.by_category, name="risk points"))
    if res.derived:
        st.subheader("Derived facts (inferred, not entered)")
        st.write(", ".join(f"`{d}`" for d in res.derived))

    st.subheader("Findings")
    if not res.findings:
        st.success("No findings - all evaluated controls passed.")
    for f in res.findings:
        r = f.rule
        with st.expander(f"{BADGE[r.severity]} {r.severity} · {r.id} · {r.name}"):
            st.write(f"**Category:** {r.category}  |  **Refs:** {r.refs or 'n/a'}  |  "
                     f"**Points:** {r.pts}  |  **Chain depth:** {f.depth}")
            if r.fix:
                st.write(f"**Remediation:** {r.fix}")
            st.code("\n".join(f.evidence), language=None)

with tab_trail:
    st.write("Each row is one **recognize-act cycle**: match → pick highest severity → fire → "
             "assert new facts. Depth > 1 means the rule used conclusions of earlier rules.")
    st.dataframe(pd.DataFrame([{
        "Cycle": f.cycle, "Depth": f.depth, "Rule": f.rule.id,
        "Severity": f"{BADGE[f.rule.severity]} {f.rule.severity}", "Conclusion": f.rule.name,
        "Facts asserted": ", ".join(f.new_facts) or "-",
        "Because": "; ".join(f.evidence)} for f in res.fired]),
        width="stretch", hide_index=True)

with tab_rules:
    cats = sorted({r.category for r in RULES})
    pick = st.multiselect("Filter by category", cats, default=cats)
    st.dataframe(pd.DataFrame([{
        "ID": r.id, "Category": r.category, "Severity": r.severity, "Name": r.name,
        "IF": r.condition_text(), "THEN assert": ", ".join(r.then) or "-",
        "Refs": r.refs, "Points": r.pts} for r in RULES if r.category in pick]),
        width="stretch", hide_index=True)
