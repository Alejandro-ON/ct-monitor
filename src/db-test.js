// Connection smoke test. Verifies the pool can reach Postgres and
// that the schema is in place.

import pool from "./db.js";

async function main() {
    // pool.query returns a promise, hence the await. The result object
    // carries rows (an array of objects) and rowCount, among others.
    const version = await pool.query("SELECT version()");
    console.log("Connected to:", version.rows[0].version.split(",")[0]);

    // Read the schema from the catalog to confirm the migration applied.
    const tables = await pool.query(`
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
        ORDER BY table_name
    `);
    console.log("Tables:", tables.rows.map(r => r.table_name).join(", "));

    // Parameterised query. $1 is a PLACEHOLDER, not string interpolation:
    // the statement and the value travel separately, so the value can
    // never be parsed as SQL. This is what prevents SQL injection.
    const count = await pool.query(
        "SELECT COUNT(*) AS n FROM candidates WHERE score >= $1",
        [5]
    );
    console.log("Candidates scoring 5 or more:", count.rows[0].n);
}

main()
    .catch((err) => {
        console.error("Connection test failed:", err.message);
        process.exitCode = 1;
    })
    // The pool holds open sockets, which keep the event loop alive and
    // stop the process from exiting. A script must close it explicitly;
    // a long-running server would not.
    .finally(() => pool.end());