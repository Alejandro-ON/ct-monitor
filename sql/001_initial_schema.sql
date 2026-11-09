/*
BIGINT -> INT with 8 bytes. Used because this table grows without limit
    and INTEGER tops out at 2.1 billion.
GENERATED ALWAYS AS IDENTITY -> SQL standard version of SERIAL.
    ALWAYS blocks manual inserts into the column, so the sequence
    cannot be broken.
TEXT -> Same as VARCHAR(n) in Postgres, same performance, no length cap.

log_url & log_index:
    They identify the exact entry position: which CT log and which
    number inside it.

issuer:
    Nullable on purpose. The field is mandatory in X.509, but a
    malformed certificate or a parser failure can leave it empty.

TIMESTAMP vs TIMESTAMPTZ:
    Same precision. TIMESTAMPTZ stores an absolute instant and
    converts to the client timezone on read. TIMESTAMP stores a
    date and time with no reference, so "20:00" says nothing about
    which zone. Needed here because the study measures time deltas.

issued_at -> when the CT log recorded the entry. This is t0.
not_before / not_after -> validity period carried inside the certificate.
observed_at -> when this pipeline saw it. DEFAULT now() fills it on insert.

dns_names:
    Every DNS name in the certificate: common name plus SANs.
    Native array instead of a separate table because the list is
    always read as a unit, never queried by element.

is_precert:
    Roughly half of CT entries are precertificates and they parse
    differently. Recorded so the split can be reported later.

certificates_log_entry_unique:
    The (log, index) pair exists once. This makes ingestion
    idempotent: a restart cannot duplicate rows.
*/

CREATE TABLE certificates (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    log_url     TEXT    NOT NULL,
    log_index   BIGINT  NOT NULL,

    issuer      TEXT,
    issued_at   TIMESTAMPTZ NOT NULL,
    not_before  TIMESTAMPTZ,
    not_after   TIMESTAMPTZ,

    dns_names   TEXT[]  NOT NULL,
    is_precert  BOOLEAN NOT NULL DEFAULT FALSE,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT certificates_log_entry_unique UNIQUE (log_url, log_index)
);

/*
One row per suspicious domain, not per sighting. The prototype stored
one row per sighting and ended up with 2155 rows for 865 real domains.

domain:
    UNIQUE because it is the natural key. id is the surrogate key,
    used for foreign keys because an 8 byte integer is cheaper to
    reference than a variable length string.

match_type:
    label    -> the brand is a whole DNS label      (strongest)
    typo     -> a label is edit distance 1 from it
    contains -> the brand appears as a substring    (weakest)

first_issued_at vs first_seen_at:
    first_issued_at -> when the earliest certificate was issued. t0.
    first_seen_at   -> when this pipeline detected it.
    The gap between them is the detection latency of the tool itself,
    around 4 minutes in the prototype. Using first_seen_at as t0 would
    measure our own delay instead of the real exposure window.

manual_label / labelled_at / label_note:
    Manual ground truth. NULL means not reviewed yet, which is the
    starting state for every candidate.

first_flagged_at / flagged_by:
    t1. First blocklist classification. NULL means still unflagged.
    Denormalised from checks on purpose: derivable by aggregation but
    read constantly, and aggregating over millions of rows per query
    is not viable. The application keeps it consistent.

CHECK constraints:
    The first two restrict the allowed values, so a typo in the code
    fails loudly instead of creating a phantom category months later.
    The last two enforce coherence: comparing two IS NULL expressions
    passes when both are null or neither is. A label needs its date,
    a flag needs its source.
*/

CREATE TABLE candidates (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    domain      TEXT    NOT NULL UNIQUE,
    brand       TEXT    NOT NULL,

    match_type  TEXT    NOT NULL,
    score       INTEGER NOT NULL,

    first_issued_at     TIMESTAMPTZ NOT NULL,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    manual_label        TEXT,
    labelled_at         TIMESTAMPTZ,
    label_note          TEXT,

    first_flagged_at    TIMESTAMPTZ,
    flagged_by          TEXT,

    CONSTRAINT candidates_match_type_valid
        CHECK (match_type IN ('label', 'typo', 'contains')),

    CONSTRAINT candidates_manual_label_valid
        CHECK (manual_label IS NULL
               OR manual_label IN ('fraudulent', 'legitimate', 'unclear')),

    CONSTRAINT candidates_label_consistent
        CHECK ((manual_label IS NULL) = (labelled_at IS NULL)),

    CONSTRAINT candidates_flag_consistent
        CHECK ((first_flagged_at IS NULL) = (flagged_by IS NULL))
);


/*
Many to many bridge table.

A certificate can reveal many domains, and a domain can appear in many
certificates (renewals, reissues, several logs). The relational model
cannot express N:M directly, so each row here is one concrete pair.

certificate_id / candidate_id:
    Foreign keys. Postgres rejects any row pointing at a parent that
    does not exist, which prevents orphan references.

ON DELETE CASCADE:
    Deletes the RELATION rows, not the entities. If a certificate is
    removed, the statement "this certificate revealed this domain"
    stops being true. The candidate itself survives, since other
    certificates may have revealed it too.

PRIMARY KEY (certificate_id, candidate_id):
    Composite key. Identifies the row and blocks duplicates in one
    go. Neither column is unique alone. No surrogate id here: nothing
    references these rows, and the table carries no attributes of its
    own.

    Note: the index this creates is ordered (certificate_id,
    candidate_id), so it does not help queries filtering by
    candidate_id alone. Add a separate index if that becomes frequent.
*/
CREATE TABLE certificate_candidates(
    certificate_id      BIGINT NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    candidate_id        BIGINT NOT NULL REFERENCES candidates(id)   ON DELETE CASCADE,

    PRIMARY KEY (certificate_id, candidate_id)
);

/*
certificates           -> stores certificates
candidates             -> stores domains
certificate_candidates -> stores the relation

checks -> stores EVENTS, not entities. Append only, never updated.
Each row is one fact: on day X, source Y was asked about domain Z.

No unique constraint here, on purpose. The same (candidate, source)
pair must repeat once per day, and that repetition is the data. Adding
UNIQUE would delete the temporal dimension, which is the study.

Growth: candidates x sources x days. With 5000 candidates, 4 sources
and 180 days that is 3.6 million rows, hence the dedicated indexes.

source:
    Which blocklist was queried. TEXT rather than an ENUM because the
    list of sources is open and adding an ENUM value needs a migration.

flagged:
    TRUE  -> the source flags this domain as malicious
    FALSE -> the source knows it and does not flag it
    NULL  -> no response, or no data

    FALSE is not a statement of safety, only that this list has not
    catalogued it. Collapsing NULL into FALSE would record an API
    outage as evidence the domain was still unflagged, which is noise
    injected into the exact measurement this project exists to make.

raw_response:
    Full API response kept so a field not modelled today can still be
    recovered later. JSONB rather than JSON: slower to insert and
    slightly larger, but parsed once and indexable, which suits a
    column written once and read often.
*/

CREATE TABLE checks(
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    candidate_id    BIGINT      NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    source          TEXT        NOT NULL,
    checked_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    flagged         BOOLEAN,
    raw_response    JSONB
);

/*
Without indexes every query is a sequential scan over the whole table.
At the expected volume that is not viable.

Dashboard filters, plain B-tree indexes:
*/
CREATE INDEX idx_candidates_brand ON candidates (brand);
CREATE INDEX idx_candidates_score ON candidates (score DESC);

/*
PARTIAL INDEXES.
They cover only the rows matching the WHERE clause, so they stay much
smaller and faster than a full index. Both of the study's working
queries filter exactly this way, so the fit is exact.
Postgres supports these; MySQL does not.
*/

-- "which candidates still need a blocklist check?"
CREATE INDEX idx_candidates_unflagged
    ON candidates (first_seen_at)
    WHERE first_flagged_at IS NULL;

-- "which candidates still need manual review, highest score first?"
CREATE INDEX idx_candidates_unlabelled
    ON candidates (score DESC)
    WHERE manual_label IS NULL;

/*
COMPOSITE INDEX.
Column order matters: this serves filtering by candidate_id, or by
candidate_id ordered by date, but NOT filtering by date alone. An
index only works on a prefix of its columns.
*/
CREATE INDEX idx_checks_candidate ON checks (candidate_id, checked_at DESC);
CREATE INDEX idx_checks_source    ON checks (source, checked_at DESC);

/*
COMMENT ON stores documentation inside the database itself. psql shows
it with \d+. Documentation that lives in the catalog cannot drift away
from the schema the way an external file can.
*/
COMMENT ON TABLE certificates IS
    'Certificates observed in CT logs. Immutable once written.';

COMMENT ON TABLE candidates IS
    'Domains flagged as potentially impersonating a tracked brand.';

COMMENT ON COLUMN candidates.first_issued_at IS
    't0 of the exposure window: issuance time of the earliest certificate revealing this domain.';

COMMENT ON COLUMN candidates.first_flagged_at IS
    't1 of the exposure window: first blocklist classification. NULL means still unflagged. Denormalised from checks by design.';

COMMENT ON TABLE checks IS
    'One row per blocklist query. flagged is three-state: NULL means the source did not answer.';