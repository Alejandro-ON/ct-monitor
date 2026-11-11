// Candidate classifier.
//
// Rebuilt from the Python prototype, which scored ~1% precision over
// 865 domains. Three defects are corrected here; see docs/engineering-log.md.

import { domainToUnicode } from "node:url";

// Target brands, already normalised: lowercase, no spaces, no accents.
export const BRANDS = [
    "correos", "agenciatributaria", "aeat", "seguridadsocial", "segsocial",
    "dgt", "sepe", "mitma",
    "santander", "bbva", "caixabank", "bankinter", "unicaja", "openbank",
    "abanca", "kutxabank", "ibercaja",
    "iberdrola", "endesa", "naturgy", "movistar", "vodafone",
    "renfe", "mapfre", "bizum"
];

// If the observed domain ends in one of these, it belongs to the real
// entity. Grow this list as recurring false positives appear: it is the
// cheapest accuracy improvement available.
const LEGIT_SUFFIXES = new Set([
    "correos.es", "correosexpress.com", "agenciatributaria.es",
    "agenciatributaria.gob.es", "seg-social.es", "seg-social.gob.es",
    "dgt.es", "sepe.es", "gob.es", "mitma.gob.es",
    "bancosantander.es", "santander.com", "santander.es", "bbva.es",
    "bbva.com", "caixabank.es", "caixabank.com", "bankinter.com",
    "unicajabanco.es", "openbank.es", "abanca.com", "kutxabank.es",
    "ibercaja.es", "iberdrola.es", "iberdrola.com", "endesa.com",
    "naturgy.es", "naturgy.com", "movistar.es", "telefonica.com",
    "vodafone.es", "renfe.com", "renfe.es", "mapfre.es", "mapfre.com",
    "bizum.es", "bizum.com"
]);

// Vocabulary typical of a Spanish phishing page.
const SUSPICIOUS_TOKENS = [
    "login", "acceso", "acceder", "clientes", "cliente", "verificacion",
    "verificar", "seguro", "seguridad", "pago", "pagos", "factura",
    "entrega", "envio", "paquete", "aduana", "reembolso", "devolucion",
    "actualizar", "confirmar", "soporte", "ayuda", "oficina",
    "particulares", "online", "movil", "portal"
];

// FIX 3b: infrastructure labels that appear in thousands of legitimate
// domains. "correo.company.com" is any organisation's mail subdomain;
// its resemblance to "correos" is a coincidence of the language.
const GENERIC_LABELS = new Set([
    "correo", "mail", "webmail", "api", "dev", "test", "staging", "www",
    "cdn", "static", "admin", "panel", "portal", "app", "demo", "pre"
]);

// Characters from other scripts that render identically to Latin ones.
// Mapping them to their Latin equivalent yields a comparable "skeleton".
const HOMOGLYPHS = new Map(Object.entries({
    "а": "a", "ɑ": "a", "α": "a", "â": "a", "á": "a", "à": "a", "ä": "a",
    "е": "e", "ё": "e", "є": "e", "ε": "e", "é": "e", "è": "e", "ê": "e",
    "о": "o", "ο": "o", "σ": "o", "ó": "o", "ò": "o", "ô": "o", "ø": "o",
    "і": "i", "ι": "i", "í": "i", "ì": "i", "î": "i", "ï": "i", "ı": "i",
    "ѕ": "s", "ş": "s", "ԁ": "d", "ϲ": "c", "с": "c", "ç": "c",
    "р": "p", "ρ": "p", "ɡ": "g", "һ": "h",
    "у": "y", "γ": "y", "ý": "y", "х": "x", "χ": "x", "м": "m",
    "ո": "n", "ñ": "n", "ν": "v", "ѵ": "v", "β": "b",
    "ł": "l", "ú": "u", "ù": "u", "û": "u", "ü": "u", "υ": "u",
    "τ": "t", "т": "t", "κ": "k", "к": "k", "г": "r"
}));

// FIX 1: leet substitutions kept SEPARATE from homoglyphs.
// Applied globally they turn hexadecimal infrastructure identifiers into
// phantom brands: 791033843470 -> ...843470... -> ...8aeato... -> "aeat".
// That single defect produced 1,140 false positives in the prototype.
// They are only applied when comparing one label against one brand.
const LEET = new Map(Object.entries({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"
}));

const MIN_BRAND_LEN = 4;      
// Lowering this to 4 lets short brands (bbva, aeat, sepe) be typo-matched.
// The risk is concrete: "seat.es" sits at distance 1 from "aeat", and SEAT
// is a real Spanish brand. Accepted for now because AD-06 means a discarded
// certificate cannot be recovered, so recall is favoured at collection time
// and precision is tuned later against the labelled set.
// MIN_CONTAINS_LEN stays at 6: substring matching on short brands was the
// prototype's main noise source and that defect is not reintroduced.

const MIN_CONTAINS_LEN = 6;   // FIX 2: shorter brands are not substring-matched

/**
 * Reduces text to a comparable skeleton: lowercase, accents stripped,
 * homoglyphs folded, everything but [a-z0-9] removed.
 */
function skeleton(text, { leet = false } = {}) {
    let out = text.toLowerCase()
        .normalize("NFKD")           // split "á" into "a" + combining accent
        .replace(/\p{M}/gu, "");     // drop the combining marks

    out = [...out].map(c => HOMOGLYPHS.get(c) ?? c).join("");
    if (leet) out = [...out].map(c => LEET.get(c) ?? c).join("");

    return out.replace(/[^a-z0-9]/g, "");
}

/**
 * Damerau-Levenshtein distance with early exit.
 *
 * Plain Levenshtein scores a transposition as 2, since it sees two
 * substitutions. Adjacent swaps are among the most common typosquatting
 * patterns ("bbav" for "bbva"), so they must count as one edit.
 */
function damerauLevenshtein(a, b, maxDist = 1) {
    if (Math.abs(a.length - b.length) > maxDist) return maxDist + 1;
    if (a === b) return 0;

    let twoBack = null;
    let previous = Array.from({ length: b.length + 1 }, (_, i) => i);

    for (let i = 1; i <= a.length; i++) {
        const current = [i];

        for (let j = 1; j <= b.length; j++) {
            current[j] = Math.min(
                previous[j] + 1,                                   // deletion
                current[j - 1] + 1,                                // insertion
                previous[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)  // substitution
            );

            // Transposition: the two characters are swapped relative to
            // each other. Needs the row from two iterations back.
            if (i > 1 && j > 1 &&
                a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
                current[j] = Math.min(current[j], twoBack[j - 2] + 1);
            }
        }

        if (Math.min(...current) > maxDist) return maxDist + 1;

        twoBack = previous;
        previous = current;
    }

    return previous[b.length];
}

/**
 * FIX 3a: machine-generated identifiers have a clear statistical
 * signature, few vowels or many digits. No real brand looks like this,
 * and they were the bulk of the prototype's noise.
 */
function looksRandom(label) {
    if (label.length < 12) return false;
    const vowels = [...label].filter(c => "aeiou".includes(c)).length;
    const digits = [...label].filter(c => c >= "0" && c <= "9").length;
    return (vowels / label.length) < 0.25 || (digits / label.length) > 0.30;
}

function isLegit(domain) {
    const d = domain.toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
    for (const suffix of LEGIT_SUFFIXES) {
        if (d === suffix || d.endsWith("." + suffix)) return true;
    }
    return false;
}

/**
 * Classifies one domain.
 *
 * @returns {{brand: string, matchType: string, score: number} | null}
 */
export function classify(domain) {
    const raw = domain.toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
    if (!raw || isLegit(raw)) return null;

    // Punycode is a signal in itself: almost no legitimate Spanish brand
    // registers IDN domains, but attackers use them for homoglyphs.
    const hadPunycode = raw.includes("xn--");
    const unicodeForm = hadPunycode ? safeDecode(raw) : raw;

    const flat = skeleton(unicodeForm);      // whole domain, NO leet
    if (!flat) return null;

    const rawLabels = unicodeForm.split(/[.\-_]/).filter(Boolean);
    const labels = rawLabels.map(p => skeleton(p)).filter(l => l && !looksRandom(l));
    const labelsLeet = rawLabels.map(p => skeleton(p, { leet: true }))
                                .filter(l => l && !looksRandom(l));
    if (labels.length === 0) return null;

    let best = null;

    for (const brand of BRANDS) {
        let matchType = null;

        if (labels.includes(brand) || labelsLeet.includes(brand)) {
            matchType = "label";                       // cleanest signal
        } else if (brand.length >= MIN_CONTAINS_LEN && flat.includes(brand)) {
            matchType = "contains";
        } else if (brand.length >= MIN_BRAND_LEN) {
            for (const label of labels) {
                if (label.length >= MIN_BRAND_LEN && damerauLevenshtein(label, brand) === 1) {
                    matchType = "typo";
                    break;
                }
            }
        }

        if (!matchType) continue;

        // A generic infrastructure label matching a brand is noise.
        if (matchType === "typo" &&
            labels.some(l => GENERIC_LABELS.has(l) && damerauLevenshtein(l, brand) <= 1)) {
            continue;
        }

        let score = { label: 4, typo: 3, contains: 2 }[matchType];

        if (hadPunycode) score += 3;
        if (skeleton(raw) !== flat) score += 2;   // real homoglyph substitution
        score += 2 * SUSPICIOUS_TOKENS.filter(t => t.length >= 4 && flat.includes(t)).length;

        const tld = raw.split(".").pop();
        if (!["es", "com", "net", "org", "eu"].includes(tld)) score += 2;
        if ((raw.match(/\./g) ?? []).length >= 3) score += 1;

        if (best === null || score > best.score) {
            best = { brand, matchType, score };
        }
    }

    return best;
}

function safeDecode(domain) {
    try {
        return domainToUnicode(domain) || domain;
    } catch {
        return domain;
    }
}