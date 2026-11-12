// Polls every log in parallel and reports progress.

import { discoverLogs } from "./logs.js";
import { LogTailer } from "./tailer.js";

const IDLE_INTERVAL_MS = 8_000;   // everything up to date: poll slowly
const BUSY_INTERVAL_MS = 200;     // backlog pending: keep draining
const REPORT_INTERVAL_MS = 5_000;

export async function run({ durationMs = 60_000 } = {}) {
    const logs = await discoverLogs();
    console.log(`Tailing ${logs.length} logs\n`);

    const tailers = logs.map(log => new LogTailer(log));

    // Per-log cooldown after an error. A failing log waits; the rest
    // carry on.
    const nextAttempt = new Map(tailers.map(t => [t.url, 0]));

    const deadline = Date.now() + durationMs;
    let totalEntries = 0;

    let lastReport = 0;

    while (Date.now() < deadline) {
        const now = Date.now();
        const ready = tailers.filter(t => nextAttempt.get(t.url) <= now);

        // allSettled, NOT all. Promise.all rejects as a whole if any
        // single promise rejects, discarding the results of the rest.
        // With nine logs routinely returning 429 and 400, that would
        // throw away good data on every cycle.
        const results = await Promise.allSettled(ready.map(t => t.poll()));

        results.forEach((result, i) => {
            const tailer = ready[i];

            if (result.status === "fulfilled") {
                totalEntries += result.value.length;
                // Respect this log's learned pacing.
                nextAttempt.set(tailer.url, Date.now() + tailer.minIntervalMs);
            } else {
                const waitMs = tailer.handleError(result.reason);
                nextAttempt.set(tailer.url, Date.now() + waitMs);
                console.warn(`  ${shortName(tailer)}: ${result.reason.message}`);
            }
        });

        if (Date.now() - lastReport >= REPORT_INTERVAL_MS) {
            report(tailers, totalEntries);
            lastReport = Date.now();
        }

        // Sleep properly only when every log is caught up. The logs
        // receive far more certificates per second than one batch per
        // cycle can read, so a fixed sleep makes the cursor fall
        // progressively further behind.
        const anyBehind = tailers.some(t => t.caughtUp === false);
        await sleep(anyBehind ? BUSY_INTERVAL_MS : IDLE_INTERVAL_MS);
    }

    return { tailers, totalEntries };
}

function report(tailers, totalEntries) {
    const errors = tailers.reduce((sum, t) => sum + t.errors, 0);
    const backlog = tailers.reduce((sum, t) => sum + t.backlog, 0);
    console.log(`entries: ${totalEntries} | backlog: ${backlog} | errors: ${errors}`);
}

function shortName(tailer) {
    return tailer.description ?? tailer.url;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}