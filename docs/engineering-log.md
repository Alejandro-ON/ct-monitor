# Engineering Log

**Project:** Certificate Transparency monitoring for the early detection of fraudulent domains targeting Spanish institutions

**Author:** Alejandro Olías Núñez
**BSc Computer Engineering, Universidad Rey Juan Carlos**
**Started:** October 2026

---

## About this document

This is an engineering record, not a tutorial and not a research paper. It documents the technical decisions taken while building the system, the reasoning behind each one, and the problems encountered along the way.

It serves three purposes:

1. **Traceability.** Every decision is justified at the moment it was made, with the information available at the time. This guards against hindsight bias when writing the final report.
2. **Reproducibility.** A third party should be able to reconstruct the environment and the system from these pages.
3. **Learning record.** The author started with no prior knowledge of JavaScript or Node.js. The concepts that had to be acquired are documented, both for personal reference and for anyone reading the repository.

The document grows by sessions. Closed entries are not rewritten: if a decision is later reversed, a new entry explains why and links back to the original. A log that hides its mistakes is not a log.

---

## Table of contents

- [1. Background](#1-background)
- [2. Research question](#2-research-question)
- [3. Ethical and legal constraints](#3-ethical-and-legal-constraints)
- [4. Phase 0: exploratory prototype](#4-phase-0-exploratory-prototype)
- [5. Architecture decisions](#5-architecture-decisions)
- [6. Development environment](#6-development-environment)
- [7. Session log](#7-session-log)
- [8. Appendix: concepts](#8-appendix-concepts)
- [9. Glossary](#9-glossary)

---

## 1. Background

### 1.1 Context

When a web server obtains a TLS certificate, the issuing Certificate Authority is required to publish it to a set of public, auditable, append-only registries known as **Certificate Transparency logs**, specified in RFC 6962. Modern browsers reject certificates that do not appear in them, which makes publication an effective requirement rather than a recommendation.

The mechanism was designed to audit Certificate Authorities, following several incidents of fraudulent issuance. It has, however, a side effect that can be exploited defensively: **a domain intending to impersonate a legitimate entity over HTTPS must publish its own existence at the moment it obtains a certificate**, typically days before the fraud campaign begins.

This is a structural information leak that the attacker cannot avoid without giving up the browser padlock.

### 1.2 Opportunity

That window, between certificate issuance and the start of fraudulent activity, has not been quantified for the Spanish ecosystem. Neither has the window that follows it: the interval between the start of activity and the moment public blocklists flag the domain as malicious.

The second window is the one that matters defensively. During that interval, reputation-based protections protect nobody.

---

## 2. Research question

**Primary**

> How much time elapses between the issuance of a certificate for a domain impersonating a Spanish institution and its classification as malicious by public blocklists?

**Secondary**

1. How many such domains are registered per day, and which sectors do they target?
2. What proportion of detections are false positives, and how does that proportion vary with the score assigned by the classifier?
3. What percentage of confirmed fraudulent domains is **never** flagged at all?

### 2.1 Acknowledged methodological limitation

The exposure window can only be measured for domains that **eventually** appear on a blocklist. Domains that are never flagged fall outside the calculation, so **the resulting figure is a lower bound on real exposure time**, not a population mean.

This is survivorship bias and it is declared explicitly. Secondary question 3 exists precisely to size it: if the proportion of never-flagged domains is high, the lower bound sits far from the true value and must be reported as such.

### 2.2 Position relative to prior work

Tools that monitor Certificate Transparency and detect typosquatting already exist: `certstream` and its reimplementations, `dnstwist`, `phishing_catcher`, `CertPatrol`, and a commercial brand-protection sector.

**The tool built here is not novel.** The contribution is measurement. None of those tools answers the question posed above, because all of them are reactive (given a brand, they report similar domains) and none publishes time series on the Spanish ecosystem.

Those tools will additionally serve as a **baseline** in the evaluation chapter, for comparison of precision and recall against the classifier developed here.

---

## 3. Ethical and legal constraints

This section was fixed **before the first line of code was written** and constrains the design of the system.

### 3.1 What the system does

It reads only the public endpoints of Certificate Transparency logs (`get-sth` and `get-entries`, as specified in RFC 6962). This is the same infrastructure browsers and CT monitors rely on.

### 3.2 What it does not do, and will not do

- **It sends no request to the certificate's domain.** No resolution, no connection, no content retrieval.
- No port scanning, directory enumeration or vulnerability assessment.
- No interaction with forms, authentication systems or any third-party service.

### 3.3 Rationale

Collection is strictly passive over information that is published deliberately and mandatorily. No third-party system is accessed, which keeps the work well clear of Article 197 bis of the Spanish Criminal Code.

### 3.4 Disclosure

If active fraudulent infrastructure targeting Spanish institutions is identified during the study, it will be reported through the appropriate coordinated disclosure channels (INCIBE-CERT or CCN-CERT depending on scope), and will not be published in the paper before those channels have acted.

### 3.5 Manual verification

Candidate domains are reviewed from their metadata: name, issuer, timestamps, and the certificate's subject alternative names. **They are not opened in a browser**, both for obvious safety reasons and because visiting them would constitute interaction with the system under study.

---

## 4. Phase 0: exploratory prototype

Before committing to the project, a throwaway prototype was built in Python with a single objective: **determine whether sufficient signal exists** to support a study.

### 4.1 Preliminary decision: do not use the public firehose

The common route for consuming CT in real time is the public `certstream.calidog.io` endpoint. It was rejected after a critical failure mode was documented: **the socket opens, stays open, and no certificates arrive**. No error is raised, so the monitor appears healthy while it is deaf.

Silent failure is unacceptable in longitudinal collection. It would be discovered weeks later, with the intervening period unrecoverably lost.

**Decision:** read the logs directly via the RFC 6962 API. More code to write, but failures are visible and the per-log cursor is under explicit control.

### 4.2 Prototype results

| Metric | Value |
|---|---|
| Active CT logs consumed | 9 |
| Certificates processed | ~14,400/min |
| First genuine candidate detected | `bbva-mi-web-particules-login.ph` |
| Detection latency | ~4 min from issuance |

The detected candidate combines a financial institution's brand, the string `particules` (a corruption of *particulares*, the term that institution uses for its retail customer area), and `login`, on a country-code top-level domain unrelated to the institution.

**Conclusion: signal exists.** Absence of detections is not the project's risk.

### 4.3 The actual problem: precision

The first measurement of the classifier yielded approximately **1% precision** over 865 unique domains. Three causes were identified.

**Cause 1: leetspeak substitutions applied globally.** The normalisation table included numeric equivalences (`4→a`, `3→e`, `7→t`) typical of typosquatting, but applied them across the entire domain. This turns hexadecimal infrastructure identifiers into phantom brands:

```
791033843470  →  ...8 4 3 4 7...  →  ...8 a e a t...  →  contains "aeat"
```

Result: 1,140 false positives attributed to the Spanish tax agency, almost all of them Amazon Web Services infrastructure.

**Cause 2: short brands matched as substrings.** Three- and four-character acronyms (`dgt`, `sepe`, `aeat`, `bbva`) occur by chance in unrelated domains. The domain `emesepeter.hu` was flagged as impersonating SEPE.

**Cause 3: generic infrastructure labels.** `correo.company.com` is any organisation's mail subdomain. Its similarity to *Correos* is a coincidence of the language, not impersonation.

### 4.4 Lesson carried into the design

This negative result is more valuable than a positive one would have been: it establishes the **baseline** against which any improvement is measured, and it identifies where the real work lies.

> Data collection is trivial. The value is in the interpretation.

The prototype is archived without continuation. Its code and data are retained as a historical reference and as a comparison point in the evaluation chapter.

---

## 5. Architecture decisions

### AD-01: Full rewrite in Node.js

**Context.** The prototype is written in Python. The production system additionally requires an API layer and a visualisation interface.

**Alternatives considered:**

| Option | Advantage | Drawback |
|---|---|---|
| A. Node throughout | single language across the stack | binary certificate parsing must be rewritten |
| B. Python collector, Node web layer | reuses the prototype | two runtimes, two deployments |

**Decision: option A.**

**Rationale.** The stated learning objective is to acquire genuine competence in Node.js. Under option B, Node would be confined to the simplest layer. A single language also simplifies deployment and keeps one concurrency model.

**Accepted cost.** The `MerkleTreeLeaf` structure parser and X.509 decoding must be reimplemented. This is the most delicate part of the system.

---

### AD-02: PostgreSQL rather than SQLite

**Context.** The prototype used SQLite, which was adequate for a proof of concept.

**Decision: PostgreSQL.**

**Rationale:**

1. **Concurrency.** SQLite serialises writes. The collector will write from multiple concurrent flows.
2. **Volume.** The checks table grows as *candidates × sources × days*. With thousands of candidates under daily monitoring over several months, this reaches millions of rows. A competent query planner and partial indexes are required.
3. **Types.** `JSONB` to store API responses without modelling every field up front, `TIMESTAMPTZ` for absolute instants, native arrays for subject alternative names.
4. **Transferability.** PostgreSQL is the de facto standard in professional environments.

---

### AD-03: Four-entity data model

**Context.** The prototype stored everything in a single `candidates` table, with heavy duplication: the same certificate appeared once per CT log that published it, producing 2,155 rows for 865 real domains.

**Decision.** Split into four tables according to each entity's lifecycle:

| Entity | Lifecycle |
|---|---|
| `certificates` | observed once, immutable |
| `candidates` | detected once, verdict evolves |
| `certificate_candidates` | N:M relation between the above |
| `checks` | one row per source query, per day |

**Rationale.** The `checks` table is what supports the temporal measurement and the one that grows without bound. Keeping it separate allows it to be indexed specifically without penalising queries over candidates.

**Deliberate denormalisation.** The `first_flagged_at` field is stored on `candidates` despite being derivable from `checks`. It is the central datum of the study and is queried constantly; aggregating over a multi-million-row table on every query would be indefensible. The cost is maintaining consistency on each check insertion, which is handled in the application layer.

---

### AD-04: Three-state boolean for check results

The `flagged` column on `checks` is nullable, and the third state is intentional:

| Value | Meaning |
|---|---|
| `true` | the source flags the domain as malicious |
| `false` | the source knows the domain and does **not** flag it |
| `NULL` | the source did not respond, or has no data |

**Rationale.** Treating an API failure as "not flagged" would introduce undetectable noise into the measurement: a day on which a source was down would be recorded as a day on which the domain remained unflagged.

---

### AD-05: Constraints enforced in the database, not only in code

**Context.** Value validation could live entirely in the application layer.

**Decision.** The schema carries `CHECK` constraints for closed value domains (`match_type`, `manual_label`) and for cross-column coherence (a label requires its timestamp; a flag requires its source).

**Rationale.** The application is not the only writer. Maintenance scripts, manual `UPDATE` statements during analysis, and future tooling all bypass it. A typo inserting `fraudlent` instead of `fraudulent` would silently corrupt the labelled ground truth, and would only surface months later when counting by category.

The database is the last line of defence and the only one that is always present.

**Not applied to `source` on `checks`.** The set of blocklist sources is open and expected to grow during the study, so an added constraint would mean a migration per new source. Validation for that column stays in the application layer. The distinction is whether the value domain is closed by design.

---

### AD-06: Persist only certificates that yield a candidate

**Context.** The original pipeline order was read, parse, store, classify. Measurement during collector development showed the logs deliver roughly 12,000 certificates per minute, which is **17 million per day**.

Storing all of them is not viable: hundreds of gigabytes within weeks, the overwhelming majority being cloud infrastructure certificates with no relation to the study.

**Decision.** A certificate is written to the database only if it reveals at least one candidate domain. Classification therefore runs **before** persistence, not after:

```
read → parse → classify → any candidates? → persist
                               │
                               └── no → discard, nothing stored
```

**Consequence.** At the candidate rate observed in the prototype, daily volume drops from 17 million rows to a few thousand. The cost is that a certificate discarded today cannot be revisited if the classifier is later improved; re-running against history is impossible because the collector reads from the tip.

**Mitigation.** The classifier is deliberately tuned for recall over precision at the collection stage. Filtering further is a question that can be answered later against stored data; recovering a discarded certificate is not.

**Note.** This constraint only became visible through measurement. It would not have been anticipated from a paper design.

---

## 6. Development environment

### 6.1 Components

| Component | Version | Role |
|---|---|---|
| Node.js | LTS | runtime for collector and API |
| PostgreSQL | 18.6 | storage |
| Git | — | version control |
| Visual Studio Code | — | editor |

### 6.2 Repository layout

```
ct-monitor/
├── .gitattributes
├── .gitignore
├── .env.example
├── README.md
├── package.json
├── docs/
│   └── engineering-log.md        ← this document
├── sql/
│   └── 001_initial_schema.sql
└── src/
    ├── index.js
    ├── db.js
    ├── collector/
    └── scoring/
```

SQL files are numbered sequentially. Each is a **migration**: a schema change applied exactly once, in order. This allows the database to be rebuilt from scratch on any machine, and constitutes the schema documentation in itself.

### 6.3 Commit policy

The repository follows **Conventional Commits**:

```
<type>: <imperative description>
```

| Type | Use |
|---|---|
| `feat` | new functionality |
| `fix` | defect correction |
| `docs` | documentation |
| `refactor` | internal change with no behavioural effect |
| `test` | tests |
| `chore` | maintenance, configuration, dependencies |

Descriptions use the present imperative (`add`, not `added`), completing the sentence *"if applied, this commit will…"*.

**Commits are small and frequent.** A granular history documents the construction process; a single final commit documents nothing. Granularity is measured in coherent changes, not in lines: every commit must leave the project in a valid state.

### 6.4 Credential handling

Credentials live in a `.env` file excluded from version control. The repository ships a `.env.example` with the structure but no real values.

> A credential committed to a repository remains in history even if removed in a later commit. The only remediations are rewriting history or rotating the credential. Prevention is trivial; remediation is not.

### 6.5 Language policy

All repository content is in English: identifiers, comments, commit messages, documentation and schema. Proper nouns are not translated: `AEAT`, `SEPE`, `Correos` and other entity names appear as they are.

### 6.6 Line endings

A `.gitattributes` file normalises all text files to `LF` inside the repository, with an exception for Windows scripts, which require `CRLF` to run.

**Rationale.** Development happens on Windows but the collector is expected to run on Linux. Without normalisation, mixed endings make diffs unreadable (an entire file appears modified when one line changed) and shell scripts fail on Linux with misleading interpreter errors. Fixing this in the repository rather than in each developer's Git configuration makes the behaviour deterministic.

---

## 7. Session log

### Session 1 · JavaScript fundamentals

Starting point: no prior knowledge of the language. Prior background in C and SQL.

Covered: Node as a runtime over the V8 engine, variable declaration, dynamic typing, template literals.

**Recorded observations:**

`const` does not impose value immutability, only binding immutability. With an object or array the contents remain mutable. The C analogue is a constant pointer to non-constant memory.

The `==` operator applies type coercion before comparing, with incoherent results (`5 + "5"` yields `"55"`, while `5 - "5"` yields `0`). **`===` is adopted systematically.** This matters for the project: API data arrives as JSON, where receiving a string in place of an expected number is routine.

---

### Session 2 · Structures and functions

Arrays, objects, the three function syntaxes, control flow, higher-order methods.

**Recorded observations:**

A JavaScript object is syntactically identical to JSON, which explains why all interaction with APIs and with the database passes through this structure.

`for...in` iterates over keys and `for...of` over values. Over an array, the former yields indices coerced to strings. `for...of` is adopted as the norm.

`filter` and `map` return new arrays; `sort` mutates in place. This is a language inconsistency and a common source of defects that are hard to locate.

---

### Session 3 · Concurrency model

**Core concept of the runtime.** Node executes JavaScript on a single thread but does not block on I/O: it delegates to the operating system, registers a continuation, and proceeds. The **event loop** services each operation as the system signals completion.

The practical consequence is that a single thread sustains thousands of concurrent connections provided the work is I/O-bound. For compute-intensive work the model is inferior to threading, since it uses one core. **This project's profile is entirely network-bound**, so the model fits.

**Equivalence with the prototype.** In Python, nine threads were spawned, one per CT log. The Node equivalent is:

```javascript
const results = await Promise.all(logs.map(log => queryLog(log)));
```

One thread, nine requests in flight, with no write synchronisation and no staggered startup.

**Observation on creation order.** Promises begin executing when created, not when awaited. Therefore:

```javascript
// Sequential: 3 s. The second promise does not exist until the first resolves.
const a = await delay(1000); const b = await delay(1000); const c = await delay(1000);

// Parallel: 1 s. All three were already in flight.
const [a, b, c] = await Promise.all([delay(1000), delay(1000), delay(1000)]);
```

**Rule adopted:** create all promises first, await afterwards.

**Note for the collector.** `Promise.all` rejects as a whole if any single promise rejects, discarding the results of the rest. Since several CT logs routinely return 429 and 400 responses, **`Promise.allSettled` will be used instead**, which waits for all and reports each outcome individually.

---

### Session 4 · Modules and dependency management

Module system, `package.json`, npm, semantic versioning.

**Decision: ES modules (`import`/`export`) over CommonJS (`require`).** They are the language standard, resolution is static (allowing the dependency graph to be analysed before execution), and they match what will be used in the web layer. This requires `"type": "module"` in `package.json`.

**On `package-lock.json`.** `package.json` declares version ranges; the lockfile records the exact versions actually installed, transitive dependencies included. **It is versioned**, because it is what guarantees reproducible builds on another machine. This is a reproducibility requirement of the study, not a style preference.

---

### Session 5 · PostgreSQL: installation, schema, first migration

**Status:** complete.

#### 5.1 Installation note

On Windows, PostgreSQL installs as a **system service**. It starts with the machine and listens in the background. There is no application to "open": what one opens is a **client** that connects to it.

The installer did not add the `bin` directory to `PATH`, so `psql` was unavailable from the terminal until added manually. Recorded because it blocks the first connection attempt and the error message does not point at the cause.

#### 5.2 Anatomy of the connection

The usual connection command is:

```powershell
psql -U postgres
```

Its fully explicit form would be:

```powershell
psql --host=localhost --port=5432 --username=postgres --dbname=postgres
```

Omitted values resolve in this order of precedence: command-line argument, environment variable (`PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`), compiled default.

| Parameter | Default |
|---|---|
| host | `localhost` |
| port | `5432` |
| dbname | same as the username |
| username | **the operating system user** |

The last one explains why `-U` is necessary: without it the client would attempt to authenticate as the Windows account, which does not exist as a PostgreSQL role.

#### 5.3 Full connection sequence

1. The system locates `psql.exe` by traversing PATH.
2. The client opens a TCP socket to `127.0.0.1:5432`.
3. It sends a startup packet of the Frontend/Backend protocol v3, carrying the requested user and database.
4. The server consults `pg_hba.conf` and determines the required authentication method (on this installation, `scram-sha-256`).
5. The SCRAM exchange runs. **The password does not travel over the network**: a cryptographic proof of knowledge is exchanged through challenge and response.
6. On successful authentication, the server **forks a dedicated process** for that connection.
7. The server emits `ReadyForQuery` and the client presents its prompt.

#### 5.4 Design implication

Step 6 has direct architectural consequences. PostgreSQL uses a **process-per-connection** model, not thread-per-connection. Each connection consumes an operating system process and several megabytes of memory, and establishing one costs tens of milliseconds across the TCP handshake, cryptographic negotiation and process creation.

**Hence the need for connection pooling** in the application layer: a small set of persistent connections shared across queries, rather than opening one per operation. This is the same reasoning behind HTTP persistent connections.

#### 5.5 Role and database

```sql
CREATE ROLE ctmonitor WITH LOGIN PASSWORD '...';
CREATE DATABASE ct_monitor OWNER ctmonitor;
```

**An application role rather than the superuser**, for three reasons: least privilege (the application never needs to drop databases or create roles, so an exploited vulnerability is contained); the credential ends up in a configuration file, and that file should not hold superuser credentials; and the role identifies the service rather than a person, so it remains meaningful if the system is deployed to a server.

In PostgreSQL a role and a user are the same entity. A role with the `LOGIN` attribute can connect; without it, it acts as a permission group.

#### 5.6 Migration applied

`sql/001_initial_schema.sql` creates four tables, six indexes and five catalog comments. Applied and verified against the live database.

Two index categories are worth recording:

**Partial indexes** cover only rows satisfying a `WHERE` clause, staying far smaller than a full index. Both of the study's working queries filter exactly this way:

```sql
CREATE INDEX idx_candidates_unlabelled
    ON candidates (score DESC)
    WHERE manual_label IS NULL;
```

**Composite indexes** only serve queries filtering on a prefix of their columns. `idx_checks_candidate (candidate_id, checked_at DESC)` serves filtering by candidate, or by candidate ordered by date, but not by date alone.

A known gap is recorded rather than pre-emptively fixed: the composite primary key on `certificate_candidates` does not support lookups by `candidate_id` alone. An index will be added if that access pattern proves frequent. Adding indexes speculatively costs write throughput and storage for no measured benefit.

#### 5.7 Catalog comments

The schema carries `COMMENT ON` statements. These are stored inside the database and displayed by `\d+`. Documentation held in the catalog cannot drift away from the schema the way an external file can.

#### 5.8 Workflow established

The sequence for every future migration:

1. Write the file.
2. Apply it with `psql -f`.
3. Verify with `\d+`.
4. Commit only after it has applied cleanly.

A migration file that has never been executed may contain syntax errors, and committing one puts the repository in a state that looks valid and is not. During development, the database is dropped and the migration reapplied as often as needed; once applied outside development, a migration is never edited, and changes go into a new numbered file.

---

### Session 6 · Node project and database connection

**Status:** complete.

npm project initialised with ES modules, `pg` installed, credentials moved to a `.env` file loaded through Node's native `--env-file`, and a connection pool module verified against the live database.

**Pool configuration.** Maximum 10 simultaneous connections, idle timeout 30 s, connection timeout 5 s. The ceiling matters: Postgres allows 100 connections in total across all clients, so a single application should stay well below it.

**An error listener on the pool is mandatory, not defensive.** Node terminates the process on an unhandled `error` event. An idle client can die on its own, for instance when the server restarts, so without a listener the collector would be killed by a dropped idle socket.

**Parameterised queries throughout.** Values travel to Postgres on a separate channel from the statement, so they never reach the SQL parser. String interpolation into a query is treated as a defect regardless of where the value came from.

**CommonJS interop.** `pg` ships as CommonJS, so only its default export is visible from an ES module. `import { Pool } from "pg"` fails; the named export has to be destructured from the default import. This applies to many long-established packages.

---

### Session 7 · Collector, parts 1 to 3

**Status:** parts 1 to 3 complete. Branch `feat/ct-collector`.

#### 7.1 Log discovery

Active logs are discovered at runtime from the list Google publishes, the same one Chrome uses. Two filters apply: state must be `usable`, and the log's temporal shard must cover the present date.

Hardcoding a list would mean polling retired logs and missing new shards within months, silently.

Nine logs were found operating at the time of writing, from Google, Cloudflare, DigiCert, Sectigo and TrustAsia.

#### 7.2 Reading loop: a throughput investigation

The reading loop went through four measured states. The sequence is recorded in full because the reasoning matters more than the final code.

| Throughput | Cause |
|---|---|
| 942 entries/min | fixed 8-second sleep every cycle, regardless of backlog |
| 942 entries/min | first fix ineffective: broken "caught up" heuristic |
| 4,745 entries/min | backlog compared against `tree_size`; continuous draining |
| 6,813 entries/min | redundant `get-sth` removed; per-log adaptive pacing |

**The instructive failure is the second row.** The first attempt inferred "caught up" from `entries.length < batchSize`, that is, "the server returned fewer than I asked for, so there is nothing left".

That is the same false assumption the module already guards against elsewhere: **servers may return fewer entries than requested even when more exist**. Advancing the cursor by the requested range would skip certificates; inferring completion from a short response stalls the loop. Both are the same mistake in different clothing, and the second was committed two paragraphs after documenting the first.

The correct test is authoritative rather than inferred: the log reports its `tree_size` on every `get-sth`, so the backlog is `tree_size - position`. No guessing required.

**Why it mattered.** With a fixed sleep the backlog grew monotonically (850 → 4,327 → 8,172 → 11,862 over one minute). The cursor would have fallen progressively further behind, and detection latency, one of the study's reported metrics, would have become meaningless.

#### 7.3 Adaptive behaviour

Two parameters are learned per log rather than configured, because no operator documents its limits.

**Batch size.** A `400` response means the log refuses a batch that large. The size halves on rejection and doubles on sustained success.

**Request pacing.** A `429` means explicit rate limiting. Earlier handling paused the log for 60 seconds and then resumed at the exact rate that triggered the limit, which would produce a sawtooth. The log now carries its own minimum interval between requests, raised on rejection and eased down after sustained success.

Both follow additive-increase, multiplicative-decrease, the same scheme TCP uses for congestion control. The system converges on each operator's tolerance without that tolerance being known in advance, and adapts if it changes.

**`Promise.allSettled`, not `Promise.all`.** With nine logs routinely returning 400 and 429, rejecting the whole batch on a single failure would discard good data every cycle.

#### 7.4 Certificate decoding

Log entries arrive as base64-encoded binary structures defined in RFC 6962 section 3.4, read field by field from a `Buffer`.

The decisive detail is the entry type. For `x509_entry`, the DER certificate follows a 3-byte length inside `leaf_input`. For `precert_entry`, `leaf_input` carries only the `TBSCertificate`, the certificate body without its signature, which no X.509 parser will accept; the full precertificate sits at the start of `extra_data`.

**Validation:** 27 consecutive entries parsed, 0 failures, **59% precertificates**. A parser mishandling `extra_data` would throw on those 16 entries and, if the exception were swallowed, would silently discard over half the stream. The ratio is the metric that proves the handling is correct, and it is checked rather than assumed.

X.509 parsing uses `node:crypto`'s built-in `X509Certificate`, so no dependency is required.

#### 7.5 Observations on log behaviour

Recorded because they affect interpretation of the final dataset, not because they indicate defects.

**Cloudflare Nimbus2026** returned zero entries with zero backlog across three separate runs. It is operating, it simply receives little traffic.

**Both Sectigo logs** alternated between zero activity and bursts of over 1,300 entries. This suggests batched rather than continuous integration, so their tree grows in steps. To be confirmed once the collector runs for hours rather than minutes.

**TrustAsia** was the only operator to rate-limit, consistently. Its learned pacing settled at 500 ms.

If a given log contributes few candidates in the final analysis, these notes distinguish low traffic from a collection defect.

#### 7.6 Outstanding

- [ ] Part 4: classifier, incorporating the three corrections from the prototype
- [ ] Part 5: persistence with `ON CONFLICT` and the bridge table
- [ ] Cursor persistence, so a restart does not lose position

---

## 8. Appendix: concepts

Concepts that had to be acquired during development, retained here for their relevance to understanding the system.

### 8.1 TCP sockets

A **socket** is a communication endpoint: the abstraction through which the operating system allows two processes to exchange data, whether on the same machine or across networks.

On Unix systems a socket **is** a file descriptor. `socket()` returns an integer equivalent to that of `open()`, on which `read()` and `write()` operate. Windows handles this through Winsock with a distinct type, but the conceptual model is identical.

**Identification.** A TCP connection is uniquely determined by a four-tuple:

```
(source IP, source port, destination IP, destination port)
```

This property is what permits multiple simultaneous connections to the same service: each uses a different source port, so the kernel can demultiplex incoming packets to the correct process.

**Ports.** A 16-bit integer. Conventional ranges:

| Range | Designation |
|---|---|
| 0–1023 | well-known (privileged on Unix) |
| 1024–49151 | registered (PostgreSQL occupies 5432) |
| 49152–65535 | ephemeral, assigned to clients |

**TCP versus UDP:**

| | TCP | UDP |
|---|---|---|
| Connection | connection-oriented | connectionless |
| Reliability | retransmits losses | no guarantees |
| Ordering | ordered delivery | may arrive out of order |
| Abstraction | byte stream | discrete datagrams |
| Control | flow and congestion | none |

A database requires TCP: the loss or reordering of a single byte would produce silent corruption.

**Property relevant to protocol design.** TCP provides a byte stream, not a message stream. Two writes of 100 bytes may be read as one of 200, or as three of 70, 90 and 40. TCP guarantees complete, ordered delivery but does not preserve message boundaries. Every protocol built on TCP must therefore delimit its own messages; the PostgreSQL protocol prefixes each message with a type byte and a four-byte length.

**Establishment.** Before `connect()` returns, the three-way handshake runs:

```
client                                 server
   │ ─────────── SYN ───────────────────> │
   │ <────────── SYN-ACK ──────────────── │
   │ ─────────── ACK ───────────────────> │
   │ ══════ connection established ═════  │
```

Three network traversals. Negligible over loopback, significant against a remote server. This cost, combined with TLS negotiation and authentication, forms part of the rationale for connection pooling.

**Loopback interface.** The address `127.0.0.1` corresponds to a virtual interface. Traffic directed there never leaves the machine: the kernel routes it internally without involving the network adapter. A service listening only on this interface is unreachable from outside.

**Relation to Node's concurrency model.** A socket can operate in non-blocking mode: rather than suspending the process until data is available, the program registers interest in the descriptor and continues. Operating systems provide mechanisms for watching many descriptors at once (`epoll` on Linux, I/O Completion Ports on Windows).

Node's event loop is precisely that: a loop that asks the system which descriptors have data ready and services only those. Hence a single thread sustaining thousands of connections.

### 8.2 Relational modelling decisions

**Natural and surrogate keys.** `candidates` carries both: `id`, an artificial integer with no meaning, and `domain`, the identifier that has meaning in the real world. The surrogate key is the primary key because foreign keys referencing it are cheaper as an 8-byte integer than as a variable-length string, and because it remains stable if domain normalisation ever changes. A `UNIQUE` constraint on `domain` preserves the natural key's guarantee.

**Many-to-many relations** cannot be expressed directly in the relational model. A certificate reveals several domains and a domain appears in several certificates, so the relation requires a bridge table where each row is one concrete pair. The composite primary key on that table both identifies rows and prevents duplicates, which is why it carries no surrogate key of its own.

**Entities and events.** Three of the four tables store entities: a certificate, a domain, a relation. `checks` stores events, and the distinction drives its design. Entity tables carry uniqueness constraints to prevent duplication; `checks` deliberately has none, because the same pair of candidate and source must repeat once per day. That repetition is the measurement.

**Arrays versus a related table.** `dns_names` is a native array rather than a separate table because the list is always read as a unit and never queried by individual element. Applying the same reasoning to `certificate_candidates` would have been wrong, since that relation does get queried from both directions. The access pattern, not normal form alone, decides.

---

## 9. Glossary

**Architecture Decision Record (ADR).** A short document capturing a single architectural decision, its context, the alternatives considered and the consequences accepted.

**Certificate Transparency.** The framework specified in RFC 6962 requiring Certificate Authorities to publish every issued certificate to public, auditable, append-only logs.

**Composite index.** An index over several columns. Column order matters: it serves queries filtering on a prefix of those columns, not on an arbitrary subset.

**Connection four-tuple.** The combination of source IP and port with destination IP and port, uniquely identifying a TCP connection.

**Connection pool.** A set of persistent connections reused across operations, avoiding establishment cost on every query.

**Denormalisation.** Deliberate duplication of derivable data to avoid recomputation. Acceptable where the query is frequent and the cost of maintaining consistency is low.

**Event loop.** Node.js's central mechanism. It continuously checks which I/O operations have completed and runs their pending continuations.

**File descriptor.** An integer identifying an I/O resource opened by a process. On Unix, sockets are file descriptors.

**Idempotence.** The property of an operation whose result is the same whether applied once or many times. In SQL this is achieved with `ON CONFLICT`.

**Migration.** A database schema change recorded in a versioned file, applied exactly once and in a defined order.

**MVCC.** Multiversion concurrency control. Each transaction observes a consistent snapshot, so reads do not block writes and vice versa.

**Natural key.** An attribute that identifies a row by its meaning in the modelled domain, as opposed to a surrogate key generated by the system.

**Partial index.** An index covering only the rows satisfying a condition. Smaller and faster where queries consistently filter on the same criterion.

**Precertificate.** A CT log entry variant issued ahead of the final certificate. Its `leaf_input` field contains only the `TBSCertificate` and is not decodable as a certificate; the full certificate resides in `extra_data`. These account for roughly half of all entries, and omitting them is a common defect in hand-rolled implementations.

**Promise.** An object representing a result not yet available. Three states: pending, fulfilled, rejected.

**Referential integrity.** The guarantee that a foreign key always points at an existing row, enforced by the database rather than by application code.

**SCRAM.** A challenge-response authentication mechanism that avoids transmitting the password.

**Socket.** An endpoint of a bidirectional communication channel, managed by the operating system.

**Surrogate key.** A system-generated identifier with no meaning outside the database, used as primary key for stability and for compact foreign keys.

**Survivorship bias.** An inferential error arising from analysing only the cases that passed a filter, ignoring those that did not.

**Typosquatting.** Registration of domains typographically close to a legitimate brand, for impersonation purposes.

**Exposure window.** In this work, the interval between issuance of a fraudulent domain's certificate and its classification as malicious by public blocklists.

**Semantic versioning (SemVer).** The `MAJOR.MINOR.PATCH` convention encoding the compatibility level of each release.

---

*Living document. Last updated: November 2026.*
