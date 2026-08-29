const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

function loadUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch (e) { return {}; }
}
function saveUsers(u) { fs.writeFileSync(USERS_FILE, JSON.stringify(u, null, 2)); }

function hashPassword(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(pw, salt, hash) {
  const h = crypto.scryptSync(pw, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(hash, 'hex'));
}

const sessions = {}; // token -> { email, exp }
function createSession(email) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions[token] = { email, exp: Date.now() + 7 * 24 * 3600 * 1000 };
  return token;
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
function authPage(msg, err) {
  const m = msg ? `<div class="msg ok">${msg}</div>` : (err ? `<div class="msg err">${err}</div>` : '');
  return html('登录', `<div class="card"><h1>wuchenyun.top</h1><h2>登录 / 注册</h2>${m}
    <form method="POST" action="/login"><label>邮箱</label><input type="email" name="email" required><label>密码</label><input type="password" name="password" required><button>登录</button></form>
    <form method="POST" action="/register" style="margin-top:14px"><label>邮箱</label><input type="email" name="email" required><label>设置密码</label><input type="password" name="password" required><button style="background:#111827">注册</button></form>
    <a class="link" href="/">返回</a></div>`);
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  const p = u.pathname;

  if (req.method === 'GET' && (p === '/' || p === '/login')) {
    const s = getSession(req);
    if (s) { res.writeHead(302, { Location: '/dashboard' }); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(authPage());
  }
  if (req.method === 'POST' && p === '/register') {
    const f = parseForm(await readBody(req));
    const email = (f.email || '').trim().toLowerCase();
    const pw = f.password || '';
    const users = loadUsers();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.end(authPage(null, '邮箱格式不对'));
    if (pw.length < 6) return res.end(authPage(null, '密码至少 6 位'));
    if (users[email]) return res.end(authPage(null, '该邮箱已注册'));
    const { salt, hash } = hashPassword(pw);
    users[email] = { salt, hash, created: Date.now() };
    saveUsers(users);
    const t = createSession(email); setCookie(res, t);
    res.writeHead(302, { Location: '/dashboard' }); return res.end();
  }
  if (req.method === 'POST' && p === '/login') {
    const f = parseForm(await readBody(req));
    const email = (f.email || '').trim().toLowerCase();
    const pw = f.password || '';
    const users = loadUsers();
    const rec = users[email];
    if (!rec || !verifyPassword(pw, rec.salt, rec.hash)) return res.end(authPage(null, '邮箱或密码错误'));
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
    const content = `<a class="logout" href="/logout">退出</a>
      <div class="card" style="max-width:560px"><h1>欢迎，${s.email}</h1>
      <p style="color:#555;font-size:15px">这里是你的私有空间，登录成功了。后续在这里填充你的内容。</p>
      <div style="margin-top:24px;padding:16px;border:1px dashed #cbd5e1;border-radius:10px;color:#94a3b8;font-size:14px">内容区（待填充）</div></div>`;
    return res.end(html('控制台', content));
  }
  res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html('404', '<div class="card"><h1>404</h1><p>页面不存在</p><a class="link" href="/">返回</a></div>'));
});

fs.mkdirSync(DATA_DIR, { recursive: true });
server.listen(PORT, () => console.log('App listening on :' + PORT + ' (secret len=' + SECRET.length + ')'));
