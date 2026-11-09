// Decoding of CT log entries into X.509 certificates.
//
// Entries arrive as base64-encoded binary structures defined in
// RFC 6962, section 3.4. They have to be read byte by byte.
//
// The structure, after base64 decoding:
//
//   [0]      1 byte   version
//   [1]      1 byte   leaf type
//   [2:10]   8 bytes  timestamp, big-endian uint64
//   [10:12]  2 bytes  entry type
//   [12:..]           the entry itself, depending on type
//
// Entry type 0 (x509_entry): a 3-byte length followed by the DER
// certificate, inside leaf_input.
//
// Entry type 1 (precert_entry): leaf_input holds only the
// TBSCertificate, which is the certificate body WITHOUT its signature
// and cannot be loaded as a certificate. The full precertificate sits
// at the start of extra_data instead.
//
// Roughly half of all log entries are precertificates. A parser that
// ignores this throws on them, swallows the error, and silently
// discards half the stream. It is the single most common defect in
// hand-rolled CT clients.

import { X509Certificate } from "node:crypto";

const ENTRY_TYPE_X509 = 0;
const ENTRY_TYPE_PRECERT = 1;

// Minimum bytes for version + leaf type + timestamp + entry type,
// plus the 3-byte length that follows.
const HEADER_BYTES = 15;

/**
 * Decodes one log entry.
 *
 * @returns {{certificate: X509Certificate, timestamp: Date, isPrecert: boolean} | null}
 *          null when the entry cannot be decoded, which is expected
 *          for a small fraction of malformed entries.
 */
export function parseEntry(leafInputB64, extraDataB64) {
    const leaf = Buffer.from(leafInputB64, "base64");
    if (leaf.length < HEADER_BYTES) return null;

    // Milliseconds since the epoch. BigInt because it is 8 bytes;
    // Number is safe here since ms timestamps stay well under 2^53.
    const timestampMs = Number(leaf.readBigUInt64BE(2));
    const entryType = leaf.readUInt16BE(10);

    let der;

    if (entryType === ENTRY_TYPE_X509) {
        // 3-byte big-endian length, then the DER certificate.
        const length = leaf.readUIntBE(12, 3);
        der = leaf.subarray(15, 15 + length);

    } else if (entryType === ENTRY_TYPE_PRECERT) {
        // leaf_input is useless here: it carries only the
        // TBSCertificate. The real precertificate is at the start of
        // extra_data, again behind a 3-byte length.
        const extra = Buffer.from(extraDataB64 ?? "", "base64");
        if (extra.length < 3) return null;

        const length = extra.readUIntBE(0, 3);
        der = extra.subarray(3, 3 + length);

    } else {
        // Unknown entry type: the format may have been extended.
        return null;
    }

    if (der.length === 0) return null;

    try {
        return {
            certificate: new X509Certificate(der),
            timestamp: new Date(timestampMs),
            isPrecert: entryType === ENTRY_TYPE_PRECERT
        };
    } catch {
        // Malformed certificate. A small fraction of entries are
        // genuinely broken, so this is expected and not an error.
        return null;
    }
}

/**
 * Extracts the fields the study needs from a parsed certificate.
 */
export function extractFields(parsed) {
    const cert = parsed.certificate;

    return {
        issuer: extractIssuerOrg(cert),
        dnsNames: extractDnsNames(cert),
        notBefore: new Date(cert.validFrom),
        notAfter: new Date(cert.validTo),
        issuedAt: parsed.timestamp,
        isPrecert: parsed.isPrecert
    };
}

/**
 * Every DNS name in the certificate: the subject common name plus the
 * subject alternative names.
 */
function extractDnsNames(cert) {
    // Deduplicate: the CN is almost always repeated among the SANs.
    const names = new Set();

    // subjectAltName comes as a single string:
    //   "DNS:example.com, DNS:*.example.com, IP Address:1.2.3.4"
    // Only DNS entries matter here.
    if (cert.subjectAltName) {
        for (const part of cert.subjectAltName.split(",")) {
            const trimmed = part.trim();
            if (trimmed.startsWith("DNS:")) {
                names.add(trimmed.slice(4).toLowerCase());
            }
        }
    }

    // subject is a multi-line string of RDNs:
    //   "C=US\nO=Example Inc\nCN=example.com"
    const cn = matchField(cert.subject, "CN");
    if (cn && cn.includes(".")) names.add(cn.toLowerCase());

    return [...names];
}

/**
 * Prefer the issuing organisation (Let's Encrypt, DigiCert Inc) over
 * the common name, which is usually an opaque intermediate identifier.
 */
function extractIssuerOrg(cert) {
    return matchField(cert.issuer, "O")
        ?? matchField(cert.issuer, "CN")
        ?? null;
}

function matchField(rdnString, key) {
    if (!rdnString) return null;
    for (const line of rdnString.split("\n")) {
        const [name, ...rest] = line.split("=");
        if (name.trim() === key) return rest.join("=").trim();
    }
    return null;
}