// Connection pool for PostgreSQL.
//
// Postgres forks a dedicated OS process per connection, so opening one
// costs tens of milliseconds between the TCP handshake, the SCRAM
// exchange and process creation. A pool keeps a small set of
// connections open and lends them out, instead of paying that cost on
// every query. Same reasoning as HTTP persistent connections.

import pg from "pg";

// pg is published as CommonJS, so the named exports are reached
// through the default import rather than destructured from the module.
const { Pool } = pg;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,

    // Upper bound on simultaneous connections. Postgres defaults to
    // 100 total, shared across every client, so a single application
    // should stay well below that.
    max: 10,

    // Close connections idle for longer than this, so the pool shrinks
    // back when the collector is quiet.
    idleTimeoutMillis: 30_000,

    // Fail fast if a connection cannot be established, rather than
    // hanging forever when Postgres is down.
    connectionTimeoutMillis: 5_000
});

// The pool emits 'error' for idle clients that die unexpectedly, for
// instance when the server restarts. Without a listener, Node treats
// an unhandled 'error' event as fatal and kills the process.
pool.on("error", (err) => {
    console.error("Unexpected error on idle client", err);
});

export default pool;