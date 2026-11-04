# ct-monitor

Real-time Certificate Transparency monitoring for the early detection of domains impersonating Spanish institutions and brands, with longitudinal measurement of how long those domains remain unflagged by public blocklists.

> Undergraduate research project · Computer Engineering, Universidad Rey Juan Carlos

---

## Why

When a server obtains a TLS certificate, the issuing authority must publish it to public, append-only **Certificate Transparency** logs (RFC 6962). Browsers reject certificates that do not appear there, which makes publication effectively mandatory.

This has a side effect that can be used defensively: a domain set up to impersonate a legitimate entity over HTTPS must announce its own existence the moment it obtains a certificate, typically days before the fraud campaign starts. The attacker cannot avoid this without giving up the browser padlock.

## Research question

> How much time elapses between the issuance of a certificate for a domain impersonating a Spanish institution, and its classification as malicious by public blocklists?

That interval is the **exposure window**: the period during which a fraudulent domain is operational and no reputation-based defence blocks it. It has not been quantified for the Spanish ecosystem.

Secondary questions:

- How many such domains appear per day, and which sectors do they target?
- What share of detections are false positives, and how does that vary with classifier score?
- What percentage of confirmed fraudulent domains is never flagged at all?

## Scope and ethics

Collection is **strictly passive**. The system reads only the public endpoints of Certificate Transparency logs (`get-sth`, `get-entries`), the same infrastructure browsers rely on.

It sends no request to any certificate's domain. No resolution, no connection, no content retrieval, no scanning, no probing, no interaction with third-party systems of any kind.

Active fraudulent infrastructure identified during the study is reported through coordinated disclosure channels before publication.

## Status

Early development. See the [engineering log](docs/engineering-log.md) for design decisions, rationale and progress.

| Stage | State |
|---|---|
| Exploratory prototype (Python) | complete, archived |
| Database schema | in progress |
| Collector (Node.js) | not started |
| Blocklist cross-checking | not started |
| Analysis and evaluation | not started |

## Stack

- **Node.js** — collector and API
- **PostgreSQL** — storage
- RFC 6962 log consumption with per-log cursors
- X.509 parsing, including precertificate entries

## Repository layout

```
docs/     engineering log and methodology
sql/      schema migrations, applied in order
src/      collector, scoring and API
```

## Prior work

This tool is not novel. [`certstream`](https://github.com/CaliDog/certstream-server), [`dnstwist`](https://github.com/elceef/dnstwist), `phishing_catcher` and commercial brand-protection services already monitor CT and detect typosquatting.

The contribution here is **measurement**, not tooling: those systems are reactive and none publishes time series for the Spanish ecosystem. They are used in this work as evaluation baselines.

## Known limitation

The exposure window can only be measured for domains that eventually reach a blocklist. Domains never flagged fall outside the calculation, so reported figures are a **lower bound**, not a population mean. This survivorship bias is quantified rather than hidden: see secondary question 3.

## Author

Alejandro Olías Núñez

## Licence

MIT
