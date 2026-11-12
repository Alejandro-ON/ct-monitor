// Ties the stages together: parse, classify, persist.
//
// Per AD-06 a certificate is only stored when it yields at least one
// candidate. At ~12,000 certificates per minute, storing everything
// would be 17 million rows a day, almost all of it cloud infrastructure
// unrelated to the study.

import { parseEntry, extractFields } from "./collector/parser.js";
import { classify } from "./scoring/classifier.js";
import { persistFinding } from "./db/repository.js";

/**
 * Processes one batch of entries from one log.
 * @returns {Promise<{parsed: number, failed: number, findings: number}>}
 */
export async function processEntries(logUrl, entries) {
    let parsed = 0, failed = 0, findings = 0;

    for (const entry of entries) {
        const result = parseEntry(entry.leafInput, entry.extraData);

        if (!result) { failed += 1; continue; }
        parsed += 1;

        const fields = extractFields(result);

        // Every DNS name in the certificate goes through the classifier.
        // One certificate can carry hundreds of names and reveal several
        // candidates at once.
        const candidates = [];
        for (const domain of fields.dnsNames) {
            const match = classify(domain);
            if (match) {
                candidates.push({
                    domain,
                    brand: match.brand,
                    matchType: match.matchType,
                    score: match.score
                });
            }
        }

        if (candidates.length === 0) continue;   // discarded, nothing stored

        try {
            await persistFinding(logUrl, entry.index, fields, candidates);
            findings += candidates.length;
        } catch (error) {
            // A write failure must not kill the collector: the stream
            // keeps moving and a lost certificate is cheaper than a
            // stopped collector.
            console.error(`persist failed for ${logUrl}@${entry.index}:`, error.message);
        }
    }

    return { parsed, failed, findings };
}