# SysAdmin Guard-AI
Forward-chaining expert system for Linux/Unix server health, security hardening and compliance (CIS, SOC 2).

## Run locally
    pip install -r requirements.txt
    streamlit run app.py
    python test_engine.py        # unit tests

## Files
| File | Purpose |
|---|---|
| engine.py | Rule/Firing/Result classes + forward-chaining InferenceEngine (written from scratch) |
| rules.py | 73 rules: 56 base (N,A,F,R,P,L,B,S) + 17 chained (X) |
| schema.py | 53 UI input facts, defaults and 3 sample profiles |
| report.py | PDF report generator (fpdf2) |
| app.py | Streamlit UI (config, dashboard, audit trail, rule base) |
| test_engine.py | Tests: rule integrity, chaining, termination, PDF |

## How inference works
1. Working memory = dict of facts (the UI inputs).
2. Agenda = every unfired rule whose conditions all hold.
3. Conflict resolution = highest severity first, then rule order.
4. Fire: record evidence, assert derived facts (e.g. weak_ssh, no_perimeter).
5. Repeat until the agenda is empty. Each rule fires once, so the loop terminates.
Chain example: N01 -> no_perimeter, A01 -> weak_ssh, X01 -> exposed_remote_access,
X04 -> vulnerable_platform, X05 -> breach_imminent, X17 -> incident response required.

## Scoring
raw points (CRITICAL 25, HIGH 15, MEDIUM 8, LOW 3, INFO 0; some chain rules override)
-> risk = min(100, raw/4). Rating: <=10 HARDENED, <=30 ACCEPTABLE, <=60 AT RISK, else CRITICAL,
with a severity floor (any CRITICAL finding => at least AT RISK).

## Deploy (public link)
1. Push this folder to a public GitHub repo (app.py at repo root).
2. share.streamlit.io -> New app -> pick repo, branch, main file `app.py` -> Deploy.
3. Put the resulting https://<name>.streamlit.app link in your submission PDF.

Note: CIS/SOC 2 mappings are topic-level references; verify exact section numbers against
the CIS Benchmark for your distribution before citing them.
