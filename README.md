<div align="center">

# account-security

**Account takeover, credential stuffing, session abuse and identity fraud for game platforms.**

`account security` · `ATO` · `credential stuffing` · `fraud detection` · `game security`

</div>

---

## Why this is game security, not just "security"

Banning a cheat account is only meaningful if getting a replacement is expensive. When fresh
accounts cost cents, when stolen accounts are resold by the thousand, and when hardware bans are
undone by a $10 spoofer, **account-level enforcement stops working** and the game's security
posture is decided in the identity layer.

This is also where cheat enforcement and fraud enforcement meet: the same underground economy
that sells cheats sells accounts, boosting, and identity-forging services. Treating them as
separate problems is why both keep regenerating.

## Contents

| Path | What it is |
|:---|:---|
| [`docs/signal-catalog.md`](docs/signal-catalog.md) | Catalogue of signals for ATO, stuffing, session abuse, boosting and resale |
| [`sql/ato_detections.sql`](sql/ato_detections.sql) | Runnable SQL detections against an auth/session schema |
| [`scripts/session_scorer.py`](scripts/session_scorer.py) | Score sessions against a signal catalogue; emits a review queue |

## Threat model

| Threat | Attacker goal | Typical signal |
|:---|:---|:---|
| Credential stuffing | Take over accounts at scale | Low-and-slow login spray across many accounts from few sources |
| Password stuffing success | Monetise the account | Login → immediate security change (email, password, MFA) |
| Session/token theft | Bypass login controls entirely | Session reuse from new device/ASN with no re-auth |
| Account resale | Transfer control | Login geography + hardware + input behaviour all change at once |
| Boosting / piloting | Change account state | Skill and input signature change while the account does not |
| Bot levelling | Create sellable inventory | Deterministic play during levelling, human play after |
| Ban evasion | Regenerate a banned identity | New account on previously-banned hardware identity |
| Payment fraud | Get paid content for free | Chargeback patterns correlated with account age and churn |

## Design principles

1. **Identity is a graph, not a field.** Player ↔ hardware ↔ payment instrument ↔ email ↔ IP ↔
   session ↔ device. Fraud shows up as edges, not as a bad value in one column.
2. **Rate-limits are not detections.** Stopping a stuffing attempt is mitigation; knowing that
   the attempt targeted 40,000 accounts from one ASN is the detection.
3. **Account age × capability is the single most useful axis.** A 3-day account that behaves
   like a 3-year veteran is either a smurf or a resale — and both matter.
4. **Change events are the highest-value log you have.** Login, then change email, then change
   password, then disable MFA, then trade items, all within an hour, is a takeover signature
   with almost no benign equivalent.
5. **Do not sacrifice good users for bad ones.** Every control needs a measured false-positive
   rate and an appeal path. Game account security that locks out legitimate players loses more
   revenue than the fraud it stops.

## Related

- [`apex-anticheat-lab`](https://github.com/NetVar1337/apex-anticheat-lab) — behavioral cheat
  detection; its HWID and account-sharing detections overlap deliberately.
- [`cheat-intel`](https://github.com/NetVar1337/cheat-intel) — the account market is one of the
  monitored source classes.

## Scope

Defensive detection work. All code operates on data the operator owns or on synthetic fixtures.
