// Reads a handful of real entries and reports what the parser makes
// of them. The precertificate ratio is the number to watch: if it
// comes out near zero, precertificates are being silently dropped.

import { discoverLogs } from "./logs.js";
import { LogTailer } from "./tailer.js";
import { parseEntry, extractFields } from "./parser.js";

const logs = await discoverLogs();
const tailer = new LogTailer(logs[0]);

console.log(`Reading from ${tailer.description}\n`);

await tailer.poll();                                   // anchor cursor
await new Promise(r => setTimeout(r, 3000));           // let it fill
const entries = await tailer.poll();

console.log(`Got ${entries.length} raw entries\n`);

let parsed = 0, failed = 0, precerts = 0;

for (const entry of entries) {
    const result = parseEntry(entry.leaf_input, entry.extra_data);

    if (!result) { failed += 1; continue; }

    parsed += 1;
    if (result.isPrecert) precerts += 1;

    if (parsed <= 3) {
        const fields = extractFields(result);
        console.log(`  issuer:   ${fields.issuer}`);
        console.log(`  names:    ${fields.dnsNames.slice(0, 4).join(", ")}${fields.dnsNames.length > 4 ? ` (+${fields.dnsNames.length - 4})` : ""}`);
        console.log(`  issued:   ${fields.issuedAt.toISOString()}`);
        console.log(`  precert:  ${fields.isPrecert}\n`);
    }
}

console.log(`parsed: ${parsed} | failed: ${failed} | precertificates: ${precerts} (${Math.round(100 * precerts / Math.max(1, parsed))}%)`);