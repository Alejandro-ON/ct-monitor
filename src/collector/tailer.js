// Reads entries from a single CT log, keeping a cursor.
//
// Each log is independent: its own position, its own batch size, its
// own error budget. A log that fails must not stop the others.

const USER_AGENT = "ct-monitor/0.1 (academic research; URJC)";

const DEFAULT_BATCH = 32;      // most logs cap responses around here
const MIN_BATCH = 1;
const REQUEST_TIMEOUT_MS = 20_000;

export class LogTailer {
    constructor(log) {
        this.url = log.url;
        this.description = log.description;

        // null means "not started yet": the first poll will anchor the
        // cursor at the current tree size, so only certificates issued
        // from now on are read. Logs hold billions of historic entries
        // and the study only needs what comes next.
        this.position = null;

        // Shrinks when a log rejects the batch size, grows back on
        // success. Different operators enforce different limits and
        // none of them advertises it.
        this.batchSize = DEFAULT_BATCH;

        this.processed = 0;
        this.errors = 0;
        this.treeSize = null;
        this.caughtUp = true;

        // Minimum gap between requests to THIS log. Starts at zero and
        // grows when the operator pushes back. Each log tolerates a
        // different rate and none of them publishes it, so it has to
        // be discovered the same way as the batch size.
        this.minIntervalMs = 0;
        this.okStreak = 0;
    }

    /**
     * One polling cycle: check the tree size, fetch whatever is new.
     * Returns the raw entries read, possibly empty.
     */
    async poll() {
        // Only ask for the tree size when we might already be caught
        // up. While a known backlog exists, re-asking doubles the
        // request count for information we already have.
        if (this.treeSize === null || this.position === null || this.position >= this.treeSize) {
            this.treeSize = await this.getTreeSize();
        }

        const treeSize = this.treeSize;

        if (this.position === null) {
            this.position = treeSize;
            this.caughtUp = true;
            return [];
        }

        if (treeSize <= this.position) {
            this.caughtUp = true;
            return [];
        }

        const start = this.position;
        const end = Math.min(start + this.batchSize - 1, treeSize - 1);

        const entries = await this.getEntries(start, end);

        this.position = start + entries.length;
        this.processed += entries.length;

        // Authoritative, not a guess: the log told us its tree size, so
        // compare against it. "Returned fewer than requested" does NOT
        // mean "no more data", which is the same trap as advancing the
        // cursor by the requested range.
        this.caughtUp = this.position >= treeSize;

        if (this.batchSize < DEFAULT_BATCH) {
            this.batchSize = Math.min(this.batchSize * 2, DEFAULT_BATCH);
        }

        // Sustained success: ease the pacing back down.
        this.okStreak += 1;
        if (this.okStreak >= 20 && this.minIntervalMs > 0) {
            this.minIntervalMs = Math.max(0, this.minIntervalMs - 100);
            this.okStreak = 0;
        }

        return entries;
    }

    async getTreeSize() {
        const data = await this.request("ct/v1/get-sth");
        return data.tree_size;
    }

    async getEntries(start, end) {
        const data = await this.request(`ct/v1/get-entries?start=${start}&end=${end}`);
        return data.entries ?? [];
    }

    /**
     * HTTP with a timeout and status-aware error handling.
     */
    async request(path) {
        // AbortSignal.timeout cancels the request after the given time.
        // Without it a hung connection blocks this log indefinitely.
        const response = await fetch(this.url + path, {
            headers: { "User-Agent": USER_AGENT },
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
        });

        if (!response.ok) {
            // Carry the status on the error so the caller can react to
            // 429 and 400 differently.
            const error = new Error(`${response.status} ${response.statusText} for ${path}`);
            error.status = response.status;
            throw error;
        }

        return response.json();
    }

    /**
     * Adjust internal state after a failure. Returns how long to wait
     * before trying this log again, in milliseconds.
     */
    handleError(error) {
        this.errors += 1;

        // 400: this log refuses a batch this large. Halve and retry.
        // No operator documents its limit, so it has to be discovered.
        if (error.status === 400) {
            this.batchSize = Math.max(MIN_BATCH, Math.floor(this.batchSize / 2));
            return 2_000;
        }

        // 429: the operator is pushing back. Slow this log down
        // permanently rather than just pausing, otherwise we return at
        // the very rate that triggered it and produce a sawtooth.
        if (error.status === 429) {
            this.okStreak = 0;
            this.minIntervalMs = Math.min(5_000, Math.max(500, this.minIntervalMs * 2));
            return 15_000;
        }

        // Anything else: network trouble, 5xx, timeout.
        return 10_000;
    }

        /** Entries known to exist that we have not read yet. */
    get backlog() {
        if (this.treeSize === null || this.position === null) return 0;
        return Math.max(0, this.treeSize - this.position);
    }
}