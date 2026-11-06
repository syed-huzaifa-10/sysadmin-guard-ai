"""SysAdmin Guard-AI - forward-chaining inference engine (pure Python).

Working memory : dict {fact_name: value}
Rule           : IF all (fact, operator, value) conditions hold THEN assert derived facts
Cycle          : match -> resolve conflict (highest severity, then rule order) -> fire -> repeat
Termination    : each rule fires at most once (refraction), so the loop always stops.
"""
import operator
from dataclasses import dataclass
from typing import Optional

OPS = {"==": operator.eq, "!=": operator.ne, ">": operator.gt,
       ">=": operator.ge, "<": operator.lt, "<=": operator.le}
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
DEFAULT_PTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    severity: str
    when: tuple                 # ((fact, op, value), ...) all must hold (AND)
    then: tuple = ()            # derived facts asserted when the rule fires
    fix: str = ""
    refs: str = ""              # e.g. "CIS:SSH | SOC2:CC6.1"
    points: Optional[int] = None

    @property
    def pts(self):
        return DEFAULT_PTS[self.severity] if self.points is None else self.points

    def matches(self, wm):
        # A condition on a fact that is not (yet) in working memory is false.
        return all(f in wm and OPS[op](wm[f], v) for f, op, v in self.when)

    def condition_text(self):
        return " AND ".join(f"{f} {op} {v}" for f, op, v in self.when)


@dataclass
class Firing:
    cycle: int
    depth: int          # 1 = fired from raw inputs, 2+ = built on derived facts
    rule: Rule
    evidence: list
    new_facts: list


@dataclass
class Result:
    rules: list
    memory: dict
    fired: list

    @property
    def findings(self):
        return sorted((x for x in self.fired if x.rule.severity != "INFO"),
                      key=lambda x: -SEV_RANK[x.rule.severity])

    @property
    def raw_points(self):
        return sum(x.rule.pts for x in self.fired)

    @property
    def risk(self):
        """Raw severity points scaled to 0-100 (raw/4, capped)."""
        return min(100, round(self.raw_points / 4))

    @property
    def rating(self):
        r = self.risk
        rating = ("HARDENED" if r <= 10 else "ACCEPTABLE" if r <= 30
                  else "AT RISK" if r <= 60 else "CRITICAL")
        # Severity floor: a single critical/high finding can never look "hardened".
        order = ["HARDENED", "ACCEPTABLE", "AT RISK", "CRITICAL"]
        worst = max((SEV_RANK[x.rule.severity] for x in self.fired), default=0)
        floor = "AT RISK" if worst == 4 else "ACCEPTABLE" if worst == 3 else "HARDENED"
        return max(rating, floor, key=order.index)

    @property
    def by_category(self):
        out = {}
        for x in self.fired:
            if x.rule.pts:
                out[x.rule.category] = out.get(x.rule.category, 0) + x.rule.pts
        return out

    @property
    def derived(self):
        return sorted({f for x in self.fired for f in x.new_facts})

    def compliance(self):
        fired = {x.rule.id for x in self.fired}
        out = {}
        for fw in ("CIS", "SOC2"):
            rel = [r for r in self.rules if fw + ":" in r.refs and r.severity != "INFO"]
            bad = [r for r in rel if r.id in fired]
            worst = max((SEV_RANK[r.severity] for r in bad), default=0)
            out[fw] = dict(
                checks=len(rel), failed=len(bad),
                pct=round(100 * (1 - len(bad) / len(rel))) if rel else 100,
                status="FAIL" if worst >= 3 else "WARN" if bad else "PASS")
        return out


class InferenceEngine:
    def __init__(self, rules):
        self.rules = list(rules)

    def run(self, facts):
        wm, depth, done, fired = dict(facts), {}, set(), []
        while True:
            agenda = [r for r in self.rules if r.id not in done and r.matches(wm)]
            if not agenda:
                break
            rule = max(agenda, key=lambda r: SEV_RANK[r.severity])  # ties -> rule order
            d = 1 + max((depth.get(f, 0) for f, _, _ in rule.when), default=0)
            evidence = [f"{f} {op} {v!r} (actual {wm[f]!r})" for f, op, v in rule.when]
            new = [f for f in rule.then if f not in wm]
            for f in rule.then:
                wm[f] = True
                depth.setdefault(f, d)
            done.add(rule.id)
            fired.append(Firing(len(fired) + 1, d, rule, evidence, new))
        return Result(self.rules, wm, fired)
