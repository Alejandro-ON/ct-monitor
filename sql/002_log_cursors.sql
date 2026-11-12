-- =====================================================================
-- 002_log_cursors.sql
--
-- Persistent read position per CT log.
--
-- Without this, every restart re-anchors each log at the current tree
-- size and loses everything emitted while the collector was down. For
-- a longitudinal study that gap is unrecoverable: the logs cannot be
-- re-read from an arbitrary past point once the window has moved on.
-- =====================================================================

CREATE TABLE log_cursors (
    -- The log URL is the natural key and nothing references these rows,
    -- so no surrogate key is needed.
    log_url    TEXT        PRIMARY KEY,

    -- Index of the next entry to read, not the last one read.
    position   BIGINT      NOT NULL,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT log_cursors_position_positive CHECK (position >= 0)
);

COMMENT ON TABLE log_cursors IS
    'Read position per CT log, so a restart resumes instead of re-anchoring at the tip.';

COMMENT ON COLUMN log_cursors.position IS
    'Index of the NEXT entry to read, not the last one read.';