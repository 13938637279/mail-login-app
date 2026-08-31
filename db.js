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

module.exports = { db, stmts };
