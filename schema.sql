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

CREATE TABLE IF NOT EXISTS categories (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  tipe TEXT NOT NULL,
  nama TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS budgets (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  kategori TEXT NOT NULL,
  bulan INTEGER NOT NULL,
  tahun INTEGER NOT NULL,
  limit_amount REAL NOT NULL,
  UNIQUE(user_id, kategori, bulan, tahun)
);

CREATE INDEX IF NOT EXISTS idx_categories_user ON categories(user_id);
CREATE INDEX IF NOT EXISTS idx_budgets_user ON budgets(user_id, bulan, tahun);

CREATE TABLE IF NOT EXISTS akun (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  nama TEXT NOT NULL,
  tipe TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_akun_user ON akun(user_id);

ALTER TABLE transactions ADD COLUMN akun_id TEXT;

CREATE TABLE IF NOT EXISTS transfers (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  dari_akun_id TEXT NOT NULL,
  ke_akun_id TEXT NOT NULL,
  jumlah REAL NOT NULL,
  catatan TEXT,
  tanggal TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transfers_user ON transfers(user_id);

ALTER TABLE utang ADD COLUMN jatuh_tempo TEXT;
