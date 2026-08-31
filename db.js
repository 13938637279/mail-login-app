// db.js —— SQLite 数据库初始化与常用查询（基于 node:sqlite，Node 22+ 内置）
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'users.db');

const fs = require('fs');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(DB_FILE);

// —— 兼容旧版（密码登录）users 表：若含 salt/hash 列则迁移到新结构（保留 email/created）——
let hasOldSchema = false;
try { db.prepare('SELECT salt FROM users LIMIT 1').get(); hasOldSchema = true; } catch (e) {}
if (hasOldSchema) {
  db.exec('ALTER TABLE users RENAME TO users_old');
  db.exec("CREATE TABLE users (email TEXT PRIMARY KEY, created INTEGER NOT NULL, role TEXT NOT NULL DEFAULT 'user', status TEXT NOT NULL DEFAULT 'active')");
  db.exec("INSERT INTO users (email, created, role, status) SELECT email, created, 'user', 'active' FROM users_old");
  db.exec('DROP TABLE users_old');
}
db.exec("CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, created INTEGER NOT NULL, role TEXT NOT NULL DEFAULT 'user', status TEXT NOT NULL DEFAULT 'active')");

// —— 预编译常用语句 ——
const stmts = {
  insUser:     db.prepare('INSERT OR IGNORE INTO users (email, created, role) VALUES (?, ?, ?)'),
  getUser:     db.prepare('SELECT email, created, role, status FROM users WHERE email = ?'),
  listUsers:   db.prepare('SELECT email, created, role, status FROM users ORDER BY created DESC'),
  setRole:     db.prepare('UPDATE users SET role = ? WHERE email = ?'),
  setStatus:   db.prepare('UPDATE users SET status = ? WHERE email = ?'),
  delUser:     db.prepare('DELETE FROM users WHERE email = ?'),
  countUsers:  db.prepare('SELECT COUNT(*) AS n FROM users'),
};

// ============ P2：比价/监控 相关表 ============
db.exec(`CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  platform TEXT NOT NULL,
  sku TEXT NOT NULL,
  title TEXT, img TEXT, url TEXT,
  last_price REAL, observed_at INTEGER,
  status TEXT NOT NULL DEFAULT 'fresh',
  UNIQUE(platform, sku)
)`);
try { db.exec('ALTER TABLE products ADD COLUMN ext TEXT'); } catch (e) {} // 幂等：加平台扩展字段(如 goods_sign)
db.exec(`CREATE TABLE IF NOT EXISTS price_points (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  price REAL,
  status TEXT NOT NULL DEFAULT 'fresh',
  UNIQUE(product_id, date)
)`);
db.exec(`CREATE TABLE IF NOT EXISTS monitors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  product_id INTEGER NOT NULL,
  target_price REAL,
  created_at INTEGER NOT NULL,
  UNIQUE(user_id, product_id)
)`);
db.exec(`CREATE TABLE IF NOT EXISTS favorites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  product_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(user_id, product_id)
)`);
db.exec(`CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL, url TEXT, title TEXT, created_at INTEGER
)`);
db.exec(`CREATE TABLE IF NOT EXISTS crawl_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  scheduled_for INTEGER,
  attempts INTEGER DEFAULT 0,
  created_at INTEGER
)`);
// 平台 OAuth/回调 事件记录（如拼多多授权回调），与本站登录完全分开
db.exec(`CREATE TABLE IF NOT EXISTS oauth_callbacks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  platform TEXT NOT NULL,
  code TEXT, state TEXT, raw TEXT,
  created_at INTEGER NOT NULL
)`);
// 目标价提醒
db.exec(`CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  product_id INTEGER NOT NULL,
  price REAL, target_price REAL,
  created_at INTEGER NOT NULL
)`);

const p2 = {
  upsertProduct: db.prepare(`INSERT INTO products (platform, sku, title, img, url, last_price, observed_at, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(platform, sku) DO UPDATE SET title=excluded.title, img=excluded.img, url=excluded.url,
      last_price=excluded.last_price, observed_at=excluded.observed_at, status=excluded.status`),
  getProductBySku: db.prepare('SELECT * FROM products WHERE platform = ? AND sku = ?'),
  getProductById:  db.prepare('SELECT * FROM products WHERE id = ?'),
  updatePrice:     db.prepare('UPDATE products SET last_price = ?, observed_at = ?, status = ? WHERE id = ?'),
  setExt:          db.prepare('UPDATE products SET ext = ? WHERE id = ?'),
  insertPricePoint: db.prepare('INSERT OR REPLACE INTO price_points (product_id, date, price, status) VALUES (?, ?, ?, ?)'),
  listPricePoints:  db.prepare('SELECT * FROM price_points WHERE product_id = ? ORDER BY date'),
  addMonitor:  db.prepare('INSERT OR IGNORE INTO monitors (user_id, product_id, target_price, created_at) VALUES (?, ?, ?, ?)'),
  removeMonitor: db.prepare('DELETE FROM monitors WHERE user_id = ? AND product_id = ?'),
  isMonitor:   db.prepare('SELECT id FROM monitors WHERE user_id = ? AND product_id = ?'),
  listMonitors: db.prepare(`SELECT m.id, m.product_id, m.target_price, m.created_at,
      p.platform, p.sku, p.title, p.img, p.url, p.last_price, p.observed_at, p.status
      FROM monitors m JOIN products p ON p.id = m.product_id WHERE m.user_id = ? ORDER BY m.created_at DESC`),
  countMonitorsByUser: db.prepare('SELECT COUNT(*) AS n FROM monitors WHERE user_id = ?'),
  // 每日报价：所有被监控的【去重商品】(按 product_id)，供一次抓取共享
  listDistinctMonitoredProducts: db.prepare(`SELECT DISTINCT p.id, p.platform, p.sku, p.title, p.last_price, p.observed_at, p.status, p.ext
      FROM monitors m JOIN products p ON p.id = m.product_id`),
  listMonitorsByProduct: db.prepare('SELECT user_id, target_price FROM monitors WHERE product_id = ?'),
  insertAlert: db.prepare('INSERT INTO alerts (user_id, product_id, price, target_price, created_at) VALUES (?, ?, ?, ?, ?)'),
  listAlertsByUser: db.prepare(`SELECT a.id, a.price, a.target_price, a.created_at, p.title, p.platform, p.url
      FROM alerts a JOIN products p ON p.id = a.product_id WHERE a.user_id = ? ORDER BY a.created_at DESC LIMIT 50`),
  addOauthCallback: db.prepare('INSERT INTO oauth_callbacks (platform, code, state, raw, created_at) VALUES (?, ?, ?, ?, ?)'),
  addLink: db.prepare('INSERT INTO links (user_id, url, title, created_at) VALUES (?, ?, ?, ?)'),
  listLinks: db.prepare('SELECT * FROM links WHERE user_id = ? ORDER BY created_at DESC'),
  delLink: db.prepare('DELETE FROM links WHERE id = ? AND user_id = ?'),
  addFavorite: db.prepare('INSERT OR IGNORE INTO favorites (user_id, product_id, created_at) VALUES (?, ?, ?)'),
  removeFavorite: db.prepare('DELETE FROM favorites WHERE user_id = ? AND product_id = ?'),
  isFavorite:  db.prepare('SELECT id FROM favorites WHERE user_id = ? AND product_id = ?'),
  listFavorites: db.prepare(`SELECT f.id, f.product_id, f.created_at,
      p.platform, p.sku, p.title, p.img, p.url, p.last_price, p.status
      FROM favorites f JOIN products p ON p.id = f.product_id WHERE f.user_id = ? ORDER BY f.created_at DESC`),
};

module.exports = { db, stmts, p2 };
