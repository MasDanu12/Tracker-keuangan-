CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  nama TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  tipe TEXT NOT NULL,
  jumlah REAL NOT NULL,
  kategori TEXT NOT NULL,
  catatan TEXT,
  tanggal TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS utang (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  tipe TEXT NOT NULL,
  nama TEXT NOT NULL,
  jumlah REAL NOT NULL,
  catatan TEXT,
  tanggal TEXT NOT NULL,
  lunas INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_utang_user ON utang(user_id);
