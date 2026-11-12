import { discoverLogs } from "./logs.js";

const logs = await discoverLogs();

console.log(`Found ${logs.length} usable logs covering today:\n`);
for (const log of logs) {
    console.log(`  [${log.operator}] ${log.description}`);
    console.log(`      ${log.url}`);
}