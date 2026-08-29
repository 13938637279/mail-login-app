const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'users.db');
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(DB_FILE);
db.exec('CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL, created INTEGER NOT NULL)');
const insUser = db.prepare('INSERT INTO users (email, salt, hash, created) VALUES (?, ?, ?, ?)');
const getUser = db.prepare('SELECT email, salt, hash, created FROM users WHERE email = ?');

function hashPassword(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(pw, salt, hash) {
  const h = crypto.scryptSync(pw, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(hash, 'hex'));
}

const sessions = {};
const loginFails = {};   // email -> { count, lockUntil }
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000; // 15 分钟
function createSession(email) {
  const t = crypto.randomBytes(32).toString('hex');
  sessions[t] = { email, exp: Date.now() + 7 * 24 * 3600 * 1000 };
  return t;
}

function readBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => resolve(body));
  });
}
function parseForm(body) {
  const o = {};
  body.split('&').forEach(kv => {
    const [k, v] = kv.split('=');
    if (k) o[decodeURIComponent(k)] = decodeURIComponent((v || '').replace(/\+/g, ' '));
  });
  return o;
}
function setCookie(res, token) {
  res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; Path=/; Max-Age=${7*24*3600}`);
}
function getCookie(req) {
  const c = req.headers.cookie || '';
  const m = c.match(/(?:^|;\s*)sid=([^;]+)/);
  return m ? m[1] : null;
}
function getSession(req) {
  const t = getCookie(req);
  if (t && sessions[t] && sessions[t].exp > Date.now()) return sessions[t];
  return null;
}

function html(title, body) {
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
  <style>body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f5f6f8;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;color:#222}
  .card{background:#fff;padding:32px;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);width:100%;max-width:380px}
  h1{font-size:22px;margin:0 0 4px}h2{font-size:18px;margin:0 0 20px;font-weight:600}
  label{display:block;font-size:13px;color:#666;margin:14px 0 6px}
  input{width:100%;box-sizing:border-box;padding:11px 12px;border:1px solid #d9dde3;border-radius:8px;font-size:15px}
  button{width:100%;margin-top:18px;padding:12px;background:#3b82f6;color:#fff;border:0;border-radius:8px;font-size:15px;cursor:pointer}
  button:hover{background:#2f6fd0}.err{color:#dc2626;font-size:13px;margin-top:10px}.ok{color:#16a34a;font-size:13px;margin-top:10px}
  .msg{font-size:14px;margin-bottom:8px}.link{display:block;text-align:center;margin-top:16px;color:#3b82f6;font-size:14px;text-decoration:none}
  a.logout{position:fixed;top:16px;right:20px;color:#666;font-size:14px;text-decoration:none}</style></head><body>${body}</body></html>`;
}
function authPage(mode, msg, err) {
  const m = msg ? `<div class="msg ok">${msg}</div>` : (err ? `<div class="msg err">${err}</div>` : '');
  if (mode === 'register') {
    return html('注册', `<div class="card"><h1>wuchenyun.top</h1><h2>创建账号</h2>${m}
      <form method="POST" action="/register"><label>邮箱</label><input type="email" name="email" required><label>设置密码</label><input type="password" name="password" required><button>注册</button></form>
      <a class="link" href="/">已有账号？去登录</a></div>`);
  }
  return html('登录', `<div class="card"><h1>wuchenyun.top</h1><h2>登录</h2>${m}
    <form method="POST" action="/login"><label>邮箱</label><input type="email" name="email" required><label>密码</label><input type="password" name="password" required><button>登录</button></form>
    <a class="link" href="/register">没有账号？去注册</a></div>`);
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  const p = u.pathname;

  if (req.method === 'GET' && (p === '/' || p === '/login')) {
    const s = getSession(req);
    if (s) { res.writeHead(302, { Location: '/dashboard' }); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(authPage('login'));
  }
  if (req.method === 'GET' && p === '/register') {
    const s = getSession(req);
    if (s) { res.writeHead(302, { Location: '/dashboard' }); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(authPage('register'));
  }
  if (req.method === 'POST' && p === '/register') {
    const f = parseForm(await readBody(req));
    const email = (f.email || '').trim().toLowerCase();
    const pw = f.password || '';
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.end(authPage('register', null, '邮箱格式不对'));
    if (pw.length < 6) return res.end(authPage('register', null, '密码至少 6 位'));
    if (getUser.get(email)) return res.end(authPage('register', null, '该邮箱已注册'));
    const { salt, hash } = hashPassword(pw);
    insUser.run(email, salt, hash, Date.now());
    const t = createSession(email); setCookie(res, t);
    res.writeHead(302, { Location: '/dashboard' }); return res.end();
  }
  if (req.method === 'POST' && p === '/login') {
    const f = parseForm(await readBody(req));
    const email = (f.email || '').trim().toLowerCase();
    const pw = f.password || '';
    const now = Date.now();
    const ff = loginFails[email];
    if (ff && ff.lockUntil > now) {
      const wait = Math.ceil((ff.lockUntil - now) / 60000);
      return res.end(authPage('login', null, `尝试次数过多，请 ${wait} 分钟后再试`));
    }
    const rec = getUser.get(email);
    if (!rec || !verifyPassword(pw, rec.salt, rec.hash)) {
      const cur = loginFails[email] || { count: 0, lockUntil: 0 };
      cur.count++;
      if (cur.count >= MAX_FAILS) { cur.lockUntil = now + LOCK_MS; cur.count = 0; }
      loginFails[email] = cur;
      if (cur.lockUntil > now) return res.end(authPage('login', null, '尝试次数过多，15 分钟后再试'));
      return res.end(authPage('login', null, '邮箱或密码错误'));
    }
    delete loginFails[email];
    const t = createSession(email); setCookie(res, t);
    res.writeHead(302, { Location: '/dashboard' }); return res.end();
  }
  if (req.method === 'GET' && p === '/logout') {
    const t = getCookie(req); if (t) delete sessions[t];
    res.writeHead(302, { Location: '/' }); return res.end();
  }
  if (req.method === 'GET' && p === '/dashboard') {
    const s = getSession(req);
    if (!s) { res.writeHead(302, { Location: '/' }); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html('控制台', `<a class="logout" href="/logout">退出</a>
      <div class="card" style="max-width:560px"><h1>欢迎，${s.email}</h1>
      <p style="color:#555;font-size:15px">这是你的私有空间，登录成功了。</p>
      <div style="margin-top:24px;padding:16px;border:1px dashed #cbd5e1;border-radius:10px;color:#94a3b8;font-size:14px">内容区（待填充）</div></div>`));
  }
  res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html('404', '<div class="card"><h1>404</h1><p>页面不存在</p><a class="link" href="/">返回</a></div>'));
});

server.listen(PORT, () => console.log('App listening on :' + PORT));
