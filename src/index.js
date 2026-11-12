// Long-running collector.
//
// Reads every usable CT log, classifies the domains it finds, and
// stores the ones that match a tracked brand.

import { discoverLogs } from "./collector/logs.js";
import { LogTailer } from "./collector/tailer.js";
import { processEntries } from "./pipeline.js";
import { loadCursors, saveCursor, stats } from "./db/repository.js";
import pool from "./db.js";

const IDLE_INTERVAL_MS = 8_000;
const BUSY_INTERVAL_MS = 200;
const REPORT_INTERVAL_MS = 30_000;
const CURSOR_SAVE_INTERVAL_MS = 15_000;

let running = true;

async function main() {
    const logs = await discoverLogs();
    const cursors = await loadCursors();

    const tailers = logs.map(log => {
        const tailer = new LogTailer(log);
        const saved = cursors.get(log.url);
        if (saved !== undefined) tailer.resumeAt(saved);
        return tailer;
    });

    const resumed = tailers.filter(t => t.position !== null).length;
    console.log(`Tailing ${tailers.length} logs (${resumed} resumed from a saved cursor)\n`);

    const nextAttempt = new Map(tailers.map(t => [t.url, 0]));
    let lastReport = 0;
    let lastCursorSave = Date.now();
    const totals = { parsed: 0, failed: 0, findings: 0 };

    while (running) {
        const now = Date.now();
        const ready = tailers.filter(t => nextAttempt.get(t.url) <= now);

        const results = await Promise.allSettled(ready.map(t => t.poll()));

        for (let i = 0; i < results.length; i++) {
            const result = results[i];
            const tailer = ready[i];

            if (result.status === "rejected") {
                const waitMs = tailer.handleError(result.reason);
                nextAttempt.set(tailer.url, Date.now() + waitMs);
                console.warn(`  ${tailer.description}: ${result.reason.message}`);
                continue;
            }

            nextAttempt.set(tailer.url, Date.now() + tailer.minIntervalMs);

            if (result.value.length === 0) continue;

            const counts = await processEntries(tailer.url, result.value);
            totals.parsed += counts.parsed;
            totals.failed += counts.failed;
            totals.findings += counts.findings;
        }

        if (Date.now() - lastCursorSave >= CURSOR_SAVE_INTERVAL_MS) {
            await saveAllCursors(tailers);
            lastCursorSave = Date.now();
        }

        if (Date.now() - lastReport >= REPORT_INTERVAL_MS) {
            const db = await stats();
            console.log(
                `parsed: ${totals.parsed} | failed: ${totals.failed} | ` +
                `findings: ${totals.findings} | stored: ${db.candidates} candidates ` +
                `(${db.strong} strong) from ${db.certificates} certificates`
            );
            lastReport = Date.now();
        }

        const anyBehind = tailers.some(t => t.caughtUp === false);
        await sleep(anyBehind ? BUSY_INTERVAL_MS : IDLE_INTERVAL_MS);
    }

    // Final save so a clean shutdown loses nothing.
    await saveAllCursors(tailers);
    console.log("Cursors saved. Exiting.");
}

async function saveAllCursors(tailers) {
    for (const tailer of tailers) {
        if (tailer.position !== null) {
            try {
                await saveCursor(tailer.url, tailer.position);
            } catch (error) {
                console.error(`cursor save failed for ${tailer.url}:`, error.message);
            }
        }
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Graceful shutdown: let the current cycle finish and persist cursors
// before exiting, rather than dropping the read position on Ctrl+C.
for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
        if (!running) process.exit(1);   // second Ctrl+C forces exit
        console.log("\nStopping after this cycle...");
        running = false;
    });
}

main()
    .catch(error => {
        console.error("Fatal:", error);
        process.exitCode = 1;
    })
    .finally(() => pool.end());