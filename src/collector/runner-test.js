import { run } from "./runner.js";

// 60 seconds: enough for a couple of polling cycles per log.
const { tailers, totalEntries } = await run({ durationMs: 60_000 });

console.log(`\nTotal raw entries read: ${totalEntries}`);
for (const t of tailers) {
        console.log(`  ${t.description}: ${t.processed} read, ${t.backlog} pending, batch ${t.batchSize}, pace ${t.minIntervalMs}ms, ${t.errors} errors`);
}