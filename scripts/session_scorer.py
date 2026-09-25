"""Score account/session activity against a signal catalogue and emit a review queue.

Usage:
    python session_scorer.py --events events.csv --out review_queue.csv

Design follows docs/signal-catalog.md:

* **breadth beats depth** — the score is driven by how many independent signals fire, not by
  how extreme a single one is;
* **explainable** — every row carries the fired signals with their values;
* **no auto-action** — output is a review queue with a recommended action *rung*.

Input CSV (one row per observed signal event):

    player_id,signal,value,ts,context

where ``signal`` is a key from SIGNALS below, ``value`` is the measured quantity, and
``context`` is free-form (ASN, country, device id, ...) carried through to the report.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

# name -> (weight, threshold, direction)
#   direction=+1  fires when value >= threshold  (e.g. hardware churn count)
#   direction=-1  fires when value <= threshold  (e.g. gap minutes before a security change)
#   direction=0   fires when abs(value) >= threshold (e.g. input drift magnitude)
@dataclass(frozen=True)
class Signal:
    name: str
    weight: float
    threshold: float
    direction: int
    description: str


SIGNALS: dict[str, Signal] = {
    "new_device_security_change":  Signal("new_device_security_change",  1.5, 60.0,  -1,
        "minutes between first-seen device and an account security change"),
    "mfa_downgrade_then_new_login": Signal("mfa_downgrade_then_new_login", 1.6, 1440.0, -1,
        "minutes between MFA downgrade and a login from an unseen device"),
    "impossible_travel_minutes":   Signal("impossible_travel_minutes",   1.2, 240.0, -1,
        "minutes between logins from two different countries"),
    "concurrent_conflicting_sessions": Signal("concurrent_conflicting_sessions", 1.0, 1.0, +1,
        "count of overlapping sessions with a conflicting device or country"),
    "hardware_churn":              Signal("hardware_churn",              1.1, 3.0,   +1,
        "distinct hardware fingerprints used by one account in the window"),
    "fingerprint_inconsistency":   Signal("fingerprint_inconsistency",   1.3, 2.0,   +1,
        "distinct disagreeing identity fields within one hardware fingerprint"),
    "banned_hw_reuse":             Signal("banned_hw_reuse",             1.7, 1.0,   +1,
        "new account appearing on a previously banned hardware identity"),
    "skill_age_mismatch":          Signal("skill_age_mismatch",          0.8, 6.0,   +1,
        "average kills on an account younger than 30 days (review-only signal)"),
    "input_signature_drift":       Signal("input_signature_drift",       1.0, 3.0,   +1,
        "z-score of the per-session input signature shift on one account"),
    "bot_levelling_entropy":       Signal("bot_levelling_entropy",       0.9, -2.0, -1,
        "input-entropy z-score during levelling (very negative = mechanical)"),
    "asymmetric_duo_ratio":        Signal("asymmetric_duo_ratio",        0.8, 2.5,   +1,
        "performance ratio between a persistent duo's two accounts"),
    "chargeback_rate":             Signal("chargeback_rate",             1.1, 2.0,   +1,
        "chargebacks on the account (count)"),
    "stuffing_source_diversity":   Signal("stuffing_source_diversity",   1.2, 200.0, +1,
        "distinct accounts targeted from one source in 24h"),
}

# Action rungs from the catalogue. Thresholds are deliberate: high friction is expensive.
RUNGS = [
    (3, "high",     "escalate: step-up auth + priority review"),
    (2, "medium",   "add to review queue"),
    (1, "low",      "silent observation; enrich profile"),
    (0, "none",     "no action"),
]


def fired(name: str, value: float) -> bool:
    s = SIGNALS[name]
    if s.direction > 0:
        return value >= s.threshold
    if s.direction < 0:
        return value <= s.threshold
    return abs(value) >= s.threshold


def score_events(df: pd.DataFrame) -> pd.DataFrame:
    unknown = set(df["signal"].unique()) - set(SIGNALS)
    if unknown:
        raise ValueError(f"unknown signal names: {sorted(unknown)}")

    rows = []
    for pid, sub in df.groupby("player_id"):
        triggered = []
        weighted = 0.0
        for _, r in sub.iterrows():
            name = str(r["signal"])
            val = float(r["value"])
            if not fired(name, val):
                continue
            s = SIGNALS[name]
            weighted += s.weight
            triggered.append((name, val, s.weight, str(r.get("context", ""))))

        # breadth: independent signal families, not raw event count
        families = {t[0] for t in triggered}
        breadth = len(families)
        breadth_bonus = 0.5 * max(0, breadth - 1) * breadth
        total = weighted + breadth_bonus

        rung, label, action = next((r for r in RUNGS if breadth >= r[0]), RUNGS[-1])

        rows.append(
            {
                "player_id": pid,
                "breadth": breadth,
                "weighted_signals": round(weighted, 2),
                "breadth_bonus": round(breadth_bonus, 2),
                "score": round(total, 2),
                "run_label": label,
                "recommended_action": action,
                "fired": "; ".join(f"{n}={v:g} (w={w})" for n, v, w, _ in triggered),
                "contexts": "; ".join(sorted({c for *_, c in triggered if c})),
                "n_events": len(sub),
            }
        )
    out = pd.DataFrame(rows)
    if out.empty:
        return out
    return out.sort_values(["breadth", "score"], ascending=False)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--events", required=True, help="CSV: player_id,signal,value,ts,context")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    df = pd.read_csv(args.events)
    required = {"player_id", "signal", "value"}
    missing = required - set(df.columns)
    if missing:
        raise SystemExit(f"events CSV missing columns: {sorted(missing)}")

    result = score_events(df)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.out, index=False)

    print(f"scored {df['player_id'].nunique()} accounts -> {args.out}")
    if not result.empty:
        counts = result["run_label"].value_counts()
        for label in ("high", "medium", "low", "none"):
            if label in counts:
                print(f"  {label:<8} {counts[label]}")
        print("\ntop of review queue:")
        cols = [c for c in ("player_id", "breadth", "score", "run_label", "fired") if c in result.columns]
        print(result[cols].head(15).to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
