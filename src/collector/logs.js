// Discovery of active Certificate Transparency logs.
//
// There is no fixed list of CT logs: they are added, retired and
// disqualified over time, and modern ones are sharded by expiry year.
// Hardcoding a list means silently monitoring dead logs within months.
//
// This reads the official list Google publishes, which is the same one
// Chrome uses to decide which logs it trusts.

const LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json";

// Identify the client. Operators run public infrastructure at their own
// cost; an anonymous scraper is indistinguishable from abuse.
const USER_AGENT = "ct-monitor/0.1 (academic research; URJC)";

/**
 * Fetches the official log list and returns the logs worth reading now.
 *
 * @returns {Promise<Array<{url: string, description: string}>>}
 */
export async function discoverLogs() {
    // fetch is built into Node since v18. No dependency needed.
    const response = await fetch(LOG_LIST_URL, {
        headers: { "User-Agent": USER_AGENT }
    });

    // fetch only rejects on network failure. A 404 or a 500 resolves
    // normally with ok === false, so the status must be checked by hand.
    // This trips up almost everyone coming from other HTTP clients.
    if (!response.ok) {
        throw new Error(`Log list fetch failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    const now = new Date();
    const logs = [];

    // The list is grouped by operator (Google, Cloudflare, DigiCert...),
    // each with several logs.
    for (const operator of data.operators ?? []) {
        for (const log of operator.logs ?? []) {
            if (!isUsable(log)) continue;
            if (!coversNow(log, now)) continue;

            logs.push({
                url: normaliseUrl(log.url),
                description: log.description ?? log.url,
                operator: operator.name ?? "unknown"
            });
        }
    }

    return logs;
}

/**
 * A log is worth reading only in the 'usable' state. 'readonly' and
 * 'retired' logs keep their history but accept nothing new, so polling
 * them spends requests for no data.
 */
function isUsable(log) {
    // state is an object with exactly one key, the state name:
    //   { "usable": { "timestamp": "2024-..." } }
    return Boolean(log.state?.usable);
}

/**
 * Modern logs are sharded by certificate expiry year. A shard only
 * accepts certificates expiring inside its window, so only the shards
 * covering the present receive new entries.
 *
 * Older logs carry no temporal_interval and accept anything.
 */
function coversNow(log, now) {
    const interval = log.temporal_interval;
    if (!interval) return true;

    const start = new Date(interval.start_inclusive);
    const end = new Date(interval.end_exclusive);

    // Guard against an unparseable date rather than silently excluding
    // the log: NaN comparisons are always false, which would drop it.
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
        return true;
    }

    return start <= now && now < end;
}

/**
 * Normalise to a single trailing slash, so endpoint paths can be
 * appended without worrying about double slashes.
 */
function normaliseUrl(url) {
    return url.replace(/\/+$/, "") + "/";
}