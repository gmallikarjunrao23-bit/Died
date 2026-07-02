import pg from 'pg';
const { Pool } = pg;

// Most managed Postgres providers (Render, Railway's public proxy, etc.)
// require SSL; Railway's *internal* network connection does not.
// This auto-detects common managed-SSL hosts, and can always be forced
// with PGSSL=true in your environment variables.
const needsSsl =
  process.env.PGSSL === 'true' ||
  /render\.com|amazonaws\.com|neon\.tech|supabase\.co/.test(process.env.DATABASE_URL || '');

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: needsSsl ? { rejectUnauthorized: false } : false,
});

export async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS kv_store (
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS kv_store_key_prefix_idx ON kv_store (key text_pattern_ops);`);
  console.log('DB ready ✓');
}

export async function kvGet(key) {
  const res = await pool.query('SELECT value FROM kv_store WHERE key = $1', [key]);
  return res.rows[0] ? res.rows[0].value : null;
}

export async function kvSet(key, value) {
  await pool.query(
    `INSERT INTO kv_store (key, value, updated_at) VALUES ($1, $2, now())
     ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = now()`,
    [key, JSON.stringify(value)]
  );
}

export async function kvList(prefix) {
  const res = await pool.query('SELECT key FROM kv_store WHERE key LIKE $1', [prefix + '%']);
  return res.rows.map((r) => r.key);
}

export async function kvDelete(key) {
  await pool.query('DELETE FROM kv_store WHERE key = $1', [key]);
}

/**
 * Deletes rows under a prefix that haven't been touched in `olderThanDays`.
 * Used for periodic cleanup of chat history / old access requests so
 * kv_store doesn't grow forever. Never call this with the `keys:` prefix.
 */
export async function kvCleanup(prefix, olderThanDays) {
  const res = await pool.query(
    `DELETE FROM kv_store WHERE key LIKE $1 AND updated_at < now() - ($2 || ' days')::interval`,
    [prefix + '%', olderThanDays]
  );
  return res.rowCount;
}

