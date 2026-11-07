/*
BIGINT -> INT with 8 bytes
GENERATED -> similar to serial (1,2,3,4,5,...)
TEXT -> Like VARCHAR(n) but without n limit

log_url & log_index:
    They identify the exact input position meaning:
    which CT register and his number

issuer:
    NOT NULL is not included due to some cirtification Trust Servicies does not
        publish who emited the https certificate

TIMESTAMP vs TIMESTAMPTZ:
    The TZ version is the one used because it provided a more acurate tiem

dns_names:
    Here we are going to save every DNS name of every certificate.

is_precert:
    This is used to know if the certificate is a precertificate or a final one.

observed_at:
    Return the actual time

certificates_log_entry_unique:
    Is a restriction that makes sure the combination of register and id is unique

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