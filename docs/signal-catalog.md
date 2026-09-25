# Signal catalogue

Signals for account takeover, credential stuffing, session abuse and account-economy fraud in a
game platform. Each signal lists what it measures, what it catches, and — importantly — the
benign explanations that produce false positives.

Acronyms: **ATO** account takeover · **SF** stuffing · **AB** account market/boosting ·
**EV** ban evasion.

---

## A. Authentication & login

### A1. Credential stuffing velocity
- **Measures:** failed logins per source (IP/ASN/device) spread across *many distinct accounts*.
- **Catches:** SF at scale.
- **Benign:** shared NAT (university dorm, mobile carrier CGNAT), a family, a LAN café.
- **Key detail:** the signal is the *account diversity per source*, not the raw failure count.
  One source failing 50,000 times on 12 accounts is a botched attack; one source failing 50,000
  times across 40,000 accounts is stuffing.

### A2. Low-and-slow stuffing
- **Measures:** per-account failure rate kept below lockout, distributed across many sources.
- **Catches:** SF designed to evade rate limiting.
- **Benign:** a user with several stale passwords.
- **Key detail:** correlate by the *password distribution*, not by source. Identical password
  orderings across unrelated accounts is a much stronger signal than any rate.

### A3. Success-after-failure clustering
- **Measures:** accounts that succeed immediately after a burst of failures elsewhere in the
  same campaign.
- **Catches:** validated credentials from a stuffing run.
- **Benign:** almost none at scale.

### A4. Impossible travel
- **Measures:** successful logins from two geographically distant points within a physically
  impossible interval.
- **Catches:** shared/sold accounts, distributed stuffing.
- **Benign:** VPN use, mobile roaming, mis-geolocated IPs, corporate egress.
- **Key detail:** use ASN + latency + device identity together; geo-IP alone is noisy.

### A5. New device + security change
- **Measures:** a first-seen device performing an account security change (email, password, MFA,
  linked platform) within N minutes of login.
- **Catches:** ATO — this is the takeover signature.
- **Benign:** legitimate user on a new PC doing housekeeping. Rarely immediate, though.
- **Key detail:** sequence matters more than any single event. `login(new device) → email change
  → password change → MFA disable → trade` in one hour has essentially no benign equivalent.

### A6. MFA downgrade / removal
- **Measures:** MFA removed, replaced, or downgraded to a weaker factor.
- **Catches:** ATO persistence.
- **Benign:** legitimate factor migration (phone lost).
- **Key detail:** a removal followed within hours by a login from a previously unseen device is
  not a phone migration.

## B. Session & token

### B1. Session reuse from new context
- **Measures:** a session token used from a new device/ASN without re-authentication.
- **Catches:** token theft, session resale.
- **Benign:** legitimate multi-device use, network change, IP churn.

### B2. Concurrent session overlap
- **Measures:** two active sessions with conflicting device identity / geography.
- **Catches:** account sharing, piloting, resale.
- **Benign:** background client left running; a shared household.

### B3. Session lifetime anomaly
- **Measures:** sessions far longer or far shorter than cohort norm.
- **Catches:** automated clients, session-farm infrastructure.
- **Benign:** AFK, crashes, patch restarts.

## C. Device & hardware identity

### C1. Hardware fingerprint churn
- **Measures:** number of distinct hardware fingerprints per account over a window.
- **Catches:** resale, sharing, evasion tooling.
- **Benign:** hardware upgrade, reformat, cloud gaming.

### C2. Fingerprint internal inconsistency
- **Measures:** a "machine" whose SMBIOS, disk serials, MAC vendor and registry GUIDs disagree
  with each other or with its own history.
- **Catches:** HWID spoofing.
- **Benign:** some legitimate hardware reports are genuinely garbage from the OEM.
  Baseline by OEM before alerting.

### C3. Banned-identity reuse
- **Measures:** a new account appearing on a hardware identity previously associated with a
  banned account.
- **Catches:** EV.
- **Benign:** resale of used hardware; a shared machine in an internet café.
- **Key detail:** the benign cases are real and common. Weight by *speed* (how soon after the
  ban) and by whether the new account also shows cheat-adjacent behavior.

### C4. Device descriptor anomalies
- **Measures:** HID/controller descriptors, firmware revisions, report rates.
- **Catches:** input emulator devices, console macro hardware.
- **Benign:** third-party controllers, accessibility devices, custom peripherals.

## D. Behavioural drift

### D1. Input signature change
- **Measures:** distribution shift in aim kinematics / input timing on the same account.
- **Catches:** piloting, sharing, ATO where the new operator plays.
- **Benign:** injury, new mouse, new sensitivity, long break, different playstyle.
- **Key detail:** the strongest form is a *regime change* — a bimodal per-session signature
  rather than a gradual drift.

### D2. Skill-vs-account-age mismatch
- **Measures:** performance far above what account age/level predicts.
- **Catches:** resale, boosting delivery, smurfing.
- **Benign:** smurfing by a legitimate player, returning veteran on a new account.
  This is a *review* signal, never an action signal on its own.

### D3. Bot-like levelling
- **Measures:** input entropy, path repetition, session regularity during the levelling phase.
- **Catches:** account farming.
- **Benign:** very new players are genuinely repetitive. Need a cohort baseline, not absolutes.

## E. Economic & social

### E1. Asymmetric duo performance
- **Measures:** a persistent duo where one account performs far above tier and the other far below.
- **Catches:** boosting, deranking-for-pay.
- **Benign:** friends of very different skill queueing together. Common and legitimate.

### E2. Serial throw / deranking pattern
- **Measures:** repeated deliberate losses followed by high-performance games.
- **Catches:** rank manipulation for resale or boosting delivery.
- **Benign:** tilt, off-days, trying a new legend/weapon.

### E3. Inventory / trade anomalies
- **Measures:** item movement patterns inconsistent with account age and prior activity.
- **Catches:** ATO monetisation, fraud.
- **Benign:** gifting, trading with friends.

### E4. Payment fraud correlation
- **Measures:** chargebacks and disputed payments correlated with account age and churn.
- **Catches:** fraud rings, stolen payment instruments.
- **Benign:** genuine disputes, expired cards, family payment confusion.

### E5. Referral / invite abuse
- **Measures:** self-referral rings, invite rewards claimed by linked accounts.
- **Catches:** reward farming.
- **Benign:** genuine friend groups, streamer communities.

---

## How to combine signals

**Breadth beats depth.** Three independent signals at moderate strength are far stronger than
one extreme signal, and far easier to defend in review or in an appeal.

**Require an evidence trail.** Every score must be decomposable into the signals that produced
it, with their values, so an analyst can answer "why was I flagged" and a reviewer can argue
with a specific number.

**Actions ladder:**

| Confidence | Action |
|:---|:---|
| Single signal | silent observation, enrich profile |
| 2 independent signals | add to review queue |
| 3+ independent signals, cross-context | step-up auth / friction |
| Confirmed, appeal-reviewed | enforcement |

Step-up authentication is the most under-used control in game account security: it converts a
detection into a mitigation without punishing a legitimate player who trips a signal.
