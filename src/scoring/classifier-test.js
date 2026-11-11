// Regression suite built from the prototype's real output. Every case
// here is a domain actually observed in CT logs.

import { classify } from "./classifier.js";

const cases = [
    // [domain, should match?, note]
    ["bbva-mi-web-particules-login.ph", true,  "the real find"],
    ["bbva.bbvaonliine.com",            true,  "typosquat"],
    ["bbav.bbvarone.it",                true,  "transposition"],
    ["santander-acceso.top",            true,  "brand + vocabulary"],

    ["240323.643471308.workers.dev",    false, "FIX 1: leet on hex id"],
    ["alex-macbook-pro.taild74ea7.ts.net", false, "FIX 1"],
    ["791033843470.amdv.dyingbirds.com",   false, "FIX 1: AWS id"],
    ["emesepeter.hu",                   false, "FIX 2: short brand substring"],
    ["correo.enseco.it",                false, "FIX 3b: generic mail label"],
    ["correo.gpaschool.com",            false, "FIX 3b"],
    ["xn--otoparasepeti-ngb.com",       false, "FIX 2: Turkish, 'sepe' by chance"],

    ["bbva.es",                         false, "legitimate"],
    ["correos.es",                      false, "legitimate"]
];

let passed = 0, failed = 0;

for (const [domain, shouldMatch, note] of cases) {
    const result = classify(domain);
    const matched = result !== null;
    const ok = matched === shouldMatch;

    if (ok) passed++; else failed++;

    const mark = ok ? "ok  " : "FAIL";
    const detail = result ? `${result.brand}/${result.matchType}/${result.score}` : "no match";
    console.log(`${mark} ${domain.padEnd(42)} ${detail.padEnd(22)} ${note}`);
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exitCode = failed > 0 ? 1 : 0;