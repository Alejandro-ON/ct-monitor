// Regression suite built from real observations.
//
// Every case here is a domain actually seen in CT logs, either during
// the Python prototype or in the first production run of the collector.
// Cases are added when a false positive or a miss is found in live data,
// so the suite grows with the study rather than being invented up front.

import { classify } from "./classifier.js";

const cases = [
    // ---- true positives ------------------------------------------------
    ["bbva-mi-web-particules-login.ph",  true,  "the real find"],
    ["bbva.bbvaonliine.com",             true,  "typosquat"],
    ["bbav.bbvarone.it",                 true,  "transposition"],
    ["santander-acceso.top",             true,  "brand + vocabulary"],

    // ---- FIX 1: leet applied globally -----------------------------------
    ["240323.643471308.workers.dev",     false, "leet on hex id"],
    ["alex-macbook-pro.taild74ea7.ts.net", false, "leet on hex id"],
    ["791033843470.amdv.dyingbirds.com", false, "leet on AWS id"],

    // ---- FIX 1b: leet on short hex labels --------------------------------
    ["cade64eb.4e47.dns-fw.canary.ops.prod.aura.acm.aws.dev", false,
        "'4e47' becomes 'aeat' under leet; too short for looksRandom"],

    // ---- FIX 2: short brands matched as substrings ------------------------
    ["emesepeter.hu",                    false, "'sepe' inside an unrelated word"],
    ["xn--otoparasepeti-ngb.com",        false, "Turkish scrapyard, 'sepe' by chance"],

    // ---- FIX 3b: generic infrastructure labels ---------------------------
    ["correo.enseco.it",                 false, "generic mail subdomain"],
    ["correo.gpaschool.com",             false, "generic mail subdomain"],

    // ---- legitimate entity domains ---------------------------------------
    ["bbva.es",                          false, "the real bank"],
    ["correos.es",                       false, "the real postal service"],
    ["forum.vodafone.co.uk",             false, "international brand domain"]
];

let passed = 0, failed = 0;

for (const [domain, shouldMatch, note] of cases) {
    const result = classify(domain);
    const matched = result !== null;
    const ok = matched === shouldMatch;

    if (ok) passed++; else failed++;

    const mark = ok ? "ok  " : "FAIL";
    const detail = result
        ? `${result.brand}/${result.matchType}/${result.score}`
        : "no match";

    console.log(`${mark} ${domain.slice(0, 48).padEnd(50)} ${detail.padEnd(22)} ${note}`);
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exitCode = failed > 0 ? 1 : 0;
