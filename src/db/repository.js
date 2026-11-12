// All database writes for the collector.
//
// Kept apart from the collector itself so the reading logic has no SQL
// in it and can be tested without a database.

import pool from "../db.js";

// ---------------------------------------------------------------------
// Cursors
// ---------------------------------------------------------------------

/**
 * Loads every saved cursor.
 * @returns {Promise<Map<string, number>>} log URL to next index to read
 */
export async function loadCursors() {
    const result = await pool.query("SELECT log_url, position FROM log_cursors");

    // position comes back as a string: node-postgres does not convert
    // BIGINT to Number automatically, because BIGINT can exceed the 53
    // bits a JavaScript number guarantees. Log indices are far below
    // that, so Number() is safe here, but the conversion must be
    // explicit or arithmetic would concatenate strings instead.
    return new Map(result.rows.map(r => [r.log_url, Number(r.position)]));
}

/**
 * Saves one cursor. Idempotent.
 */
export async function saveCursor(logUrl, position) {
    await pool.query(
        `INSERT INTO log_cursors (log_url, position)
         VALUES ($1, $2)
         ON CONFLICT (log_url) DO UPDATE
            SET position = EXCLUDED.position,
                updated_at = now()`,
        [logUrl, position]
    );
}

// ---------------------------------------------------------------------
// Certificates and candidates
// ---------------------------------------------------------------------

/**
 * Stores one certificate together with the candidates it revealed.
 *
 * Per AD-06, a certificate is only persisted when it yields at least
 * one candidate. The caller enforces that; this function assumes it.
 *
 * Everything runs in a single transaction: a certificate row without
 * its candidate rows would be a certificate stored for no reason, and
 * candidates without their certificate would lose their provenance.
 *
 * @param {string} logUrl
 * @param {number} logIndex
 * @param {object} fields    output of extractFields()
 * @param {Array<{domain: string, brand: string, matchType: string, score: number}>} candidates
 */
export async function persistFinding(logUrl, logIndex, fields, candidates) {
    // A transaction needs ONE specific connection, not the pool: the
    // statements must all travel over the same session.
    const client = await pool.connect();

    try {
        await client.query("BEGIN");

        const certificateId = await insertCertificate(client, logUrl, logIndex, fields);

        for (const candidate of candidates) {
            const candidateId = await upsertCandidate(client, candidate, fields.issuedAt);
            await linkCertificateToCandidate(client, certificateId, candidateId);
        }

        await client.query("COMMIT");
        return certificateId;

    } catch (error) {
        await client.query("ROLLBACK");
        throw error;

    } finally {
        // Always return the connection to the pool. Without this the
        // pool is exhausted after `max` failures and the process hangs
        // with no error message.
        client.release();
    }
}

/**
 * Inserts a certificate, or returns the id of the existing row.
 *
 * ON CONFLICT DO NOTHING combined with RETURNING gives back no row on
 * conflict, which would leave certificateId undefined on a restart.
 * The CTE covers both paths: the inserted id if there was one, the
 * existing id otherwise.
 */
async function insertCertificate(client, logUrl, logIndex, fields) {
    const result = await client.query(
        `WITH inserted AS (
             INSERT INTO certificates
                 (log_url, log_index, issuer, issued_at,
                  not_before, not_after, dns_names, is_precert)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (log_url, log_index) DO NOTHING
             RETURNING id
         )
         SELECT id FROM inserted
         UNION ALL
         SELECT id FROM certificates
          WHERE log_url = $1 AND log_index = $2
         LIMIT 1`,
        [
            logUrl,
            logIndex,
            fields.issuer,
            fields.issuedAt,
            fields.notBefore,
            fields.notAfter,
            fields.dnsNames,     // JS array maps to Postgres TEXT[] directly
            fields.isPrecert
        ]
    );

    return result.rows[0].id;
}

/**
 * Inserts a candidate or updates the existing one.
 *
 * A domain can be revealed by many certificates over time. The row
 * keeps the HIGHEST score ever assigned and the EARLIEST issuance seen,
 * because first_issued_at is t0 of the exposure window and must not
 * drift forward when a renewal is observed later.
 */
async function upsertCandidate(client, candidate, issuedAt) {
    const result = await client.query(
        `INSERT INTO candidates
             (domain, brand, match_type, score, first_issued_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (domain) DO UPDATE
            SET score = GREATEST(candidates.score, EXCLUDED.score),
                first_issued_at = LEAST(candidates.first_issued_at,
                                        EXCLUDED.first_issued_at)
         RETURNING id`,
        [candidate.domain, candidate.brand, candidate.matchType, candidate.score, issuedAt]
    );

    // Unlike DO NOTHING, DO UPDATE always produces a row, so RETURNING
    // is reliable here and no CTE is needed.
    return result.rows[0].id;
}

async function linkCertificateToCandidate(client, certificateId, candidateId) {
    await client.query(
        `INSERT INTO certificate_candidates (certificate_id, candidate_id)
         VALUES ($1, $2)
         ON CONFLICT DO NOTHING`,
        [certificateId, candidateId]
    );
}

// ---------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------

export async function stats() {
    const result = await pool.query(`
        SELECT
            (SELECT COUNT(*) FROM certificates) AS certificates,
            (SELECT COUNT(*) FROM candidates)   AS candidates,
            (SELECT COUNT(*) FROM candidates WHERE score >= 8) AS strong
    `);
    return result.rows[0];
}