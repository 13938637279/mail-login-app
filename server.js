const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'users.db');
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase();

fs.mkdirSync(DATA_DIR, { recursive: true });
function loadSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  const sf = path.join(DATA_DIR, '.session_secret');
  try { const s = fs.readFileSync(sf, 'utf8').trim(); if (s) return s; } catch (e) {}
  const s = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(sf, s);
  return s;
}
const SECRET = loadSecret();

const db = new DatabaseSync(DB_FILE);
// 旧版(密码登录)的 users 表有 salt/hash 非空列, 会导致 email-code 登录插不进用户 → 检测到旧结构就迁移重建(保留 email/created)
let hasOldSchema = false;
try { db.prepare('SELECT salt FROM users LIMIT 1').get(); hasOldSchema = true; } catch (e) {}
if (hasOldSchema) {
  db.exec('ALTER TABLE users RENAME TO users_old');
  db.exec("CREATE TABLE users (email TEXT PRIMARY KEY, created INTEGER NOT NULL, role TEXT NOT NULL DEFAULT 'user', status TEXT NOT NULL DEFAULT 'active')");
  db.exec("INSERT INTO users (email, created, role, status) SELECT email, created, 'user', 'active' FROM users_old");
  db.exec('DROP TABLE users_old');
}
db.exec("CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, created INTEGER NOT NULL, role TEXT NOT NULL DEFAULT 'user', status TEXT NOT NULL DEFAULT 'active')");
const insUser = db.prepare('INSERT OR IGNORE INTO users (email, created, role) VALUES (?, ?, ?)');
const getUser = db.prepare('SELECT email, created, role, status FROM users WHERE email = ?');
const listUsers = db.prepare('SELECT email, created, role, status FROM users ORDER BY created DESC');
const setRole = db.prepare('UPDATE users SET role = ? WHERE email = ?');
const setStatus = db.prepare('UPDATE users SET status = ? WHERE email = ?');
const delUser = db.prepare('DELETE FROM users WHERE email = ?');
const countUsers = db.prepare('SELECT COUNT(*) AS n FROM users');

// ---- 发信(SMTP) ----
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST || '',
  port: Number(process.env.SMTP_PORT || 465),
  secure: Number(process.env.SMTP_PORT || 465) === 465,
  auth: { user: process.env.SMTP_USER || '', pass: process.env.SMTP_PASS || '' }
});
const MAIL_FROM = process.env.SMTP_FROM || process.env.SMTP_USER || '';

// ---- 邮箱验证码 ----
const emailCodes = {};
const CODE_LIFE = 5 * 60 * 1000;
function sendCode(email) {
  const code = String(crypto.randomInt(100000, 1000000));
  emailCodes[email] = { code, exp: Date.now() + CODE_LIFE };
  const txt = `【wuchenyun.top】你的登录验证码是 ${code}，5 分钟内有效。若非本人操作请忽略。`;
  return mailer.sendMail({ from: MAIL_FROM, to: email, subject: 'wuchenyun.top 登录验证码', text: txt });
}

// ---- 会话(3天滑动) ----
const SESSION_MS = 3 * 24 * 3600 * 1000;
function b64url(buf) { return Buffer.from(buf).toString('base64url'); }
function signHmac(payload) { return crypto.createHmac('sha256', SECRET).update(payload).digest('base64url'); }
function createSession(email) {
  const payload = b64url(JSON.stringify({ email, exp: Date.now() + SESSION_MS }));
  return payload + '.' + signHmac(payload);
}
function getSession(req) {
  const t = getCookie(req);
  if (!t) return null;
  const idx = t.lastIndexOf('.');
  if (idx < 0) return null;
  const payload = t.slice(0, idx), sig = t.slice(idx + 1);
  const expected = signHmac(payload);
  if (sig.length !== expected.length) return null;
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (data && data.exp > Date.now()) return { email: data.email };
  } catch (e) {}
  return null;
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
  res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; Path=/; Max-Age=${Math.floor(SESSION_MS / 1000)}`);
}
function clearCookie(res) {
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
}
function getCookie(req) {
  const c = req.headers.cookie || '';
  const m = c.match(/(?:^|;\s*)sid=([^;]+)/);
  return m ? m[1] : null;
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
  a.logout{position:fixed;top:16px;right:20px;color:#666;font-size:14px;text-decoration:none}.row{display:flex;gap:10px}.row button{width:auto;margin:0;padding:11px 14px;white-space:nowrap}
  table{width:100%;border-collapse:collapse;margin-top:12px}.tp{text-align:left;padding:8px;border-bottom:1px solid #eee;font-size:14px}.tp th{border-bottom:2px solid #eee;color:#555;font-weight:600}.pp{background:#fff}.sel{background:#f8fafc}
  .btn-sm{padding:4px 10px;font-size:12px;margin:0 3px;width:auto}.adm{color:#dc2626;font-weight:600}.usr{color:#16a34a}</style></head><body>${body}</body></html>`;
}

function authPage(msg, err) {
  const m = msg ? `<div class="msg ok">${msg}</div>` : (err ? `<div class="msg err">${err}</div>` : '');
  return html('登录', `<div class="card"><h1>wuchenyun.top</h1><h2>邮箱验证码登录</h2>${m}
    <label>邮箱</label><div class="row"><input type="email" id="email" placeholder="you@example.com"><button onclick="send()">获取验证码</button></div>
    <label>验证码</label><input type="text" id="code" placeholder="输入 6 位验证码">
    <button onclick="login()">登录</button>
    <p id="hint" class="msg err"></p></div>
    <script>
    async function send(){var em=document.getElementById('email').value;var h=document.getElementById('hint');if(!em||!em.includes('@')){h.textContent='请输入正确邮箱';return}h.textContent='发送中...';var r=await fetch('/send-code',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'email='+encodeURIComponent(em)});var t=await r.text();h.textContent=t;h.style.color=r.ok?'#16a34a':'#dc2626'}
    async function login(){var em=document.getElementById('email').value;var c=document.getElementById('code').value;var h=document.getElementById('hint');if(!em||!c){h.textContent='填邮箱和验证码';return}var r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'email='+encodeURIComponent(em)+'&code='+encodeURIComponent(c)});if(r.redirected){location.href=r.url}else{var t=await r.text();h.textContent=t;h.style.color='#dc2626'}}
    </script></body></html>`);
}

function userPage(email) {
  return html('控制台', `<a class="logout" href="/logout">退出</a>
    <div class="card" style="max-width:560px"><h1>欢迎，${email}</h1>
    <p style="color:#555;font-size:15px">这是你的私有空间。</p>
    <div style="margin-top:24px;padding:16px;border:1px dashed #cbd5e1;border-radius:10px;color:#94a3b8;font-size:14px">内容区（待填充）</div></div>`);
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  const p = u.pathname;

  if (req.method === 'GET' && (p === '/' || p === '/login')) {
    const s = getSession(req);
    if (s) { res.writeHead(302, { Location: (getUser.get(s.email)||{}).role === 'admin' ? '/admin' : '/user' }); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(authPage());
  }
  if (req.method === 'POST' && p === '/send-code') {
    const f = parseForm(await readBody(req));
    const email = (f.email || '').trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) { res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('邮箱格式不对'); }
    const rec = getUser.get(email);
    if (rec && rec.status === 'banned') { res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('该账号已被封禁'); }
    try { await sendCode(email); res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('验证码已发送，请查收邮箱'); }
    catch (e) { res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('发送失败，请检查邮件服务配置'); }
  }
  if (req.method === 'POST' && p === '/login') {
    const f = parseForm(await readBody(req));
    const email = (f.email || '').trim().toLowerCase();
    const code = (f.code || '').trim();
    const rec = emailCodes[email];
    if (!rec || rec.exp < Date.now() || rec.code !== code) { res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('验证码错误或已过期'); }
    delete emailCodes[email];
    let user = getUser.get(email);
    if (!user) { insUser.run(email, Date.now(), email === ADMIN_EMAIL ? 'admin' : 'user'); user = getUser.get(email); }
    else if (email === ADMIN_EMAIL && user.role !== 'admin') { setRole.run('admin', email); user = getUser.get(email); }
    if (!user) { res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('注册失败，请重试'); }
    if (user.status === 'banned') { res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('该账号已被封禁'); }
    const t = createSession(email); setCookie(res, t);
    res.writeHead(302, { Location: user.role === 'admin' ? '/admin' : '/user' }); return res.end();
  }
  if (req.method === 'GET' && p === '/logout') { clearCookie(res); res.writeHead(302, { Location: '/' }); return res.end(); }

  // ---- 普通用户界面 ----
  if (req.method === 'GET' && p === '/user') {
    const s = getSession(req); if (!s) { res.writeHead(302, { Location: '/' }); return res.end(); }
    const u = getUser.get(s.email);
    if (u && u.status === 'banned') { clearCookie(res); res.writeHead(302, { Location: '/' }); return res.end(); }
    setCookie(res, createSession(s.email));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(userPage(s.email));
  }

  // ---- 管理界面 ----
  if (req.method === 'GET' && p === '/admin') {
    const s = getSession(req); if (!s) { res.writeHead(302, { Location: '/' }); return res.end(); }
    const u = getUser.get(s.email); if (!u || u.role !== 'admin') { res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('403 无权限'); }
    setCookie(res, createSession(s.email));
    const n = countUsers.get().n;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html('管理后台', `<a class="logout" href="/logout">退出</a>
      <div class="card" style="max-width:720px"><h1>管理后台</h1><p>总用户数：<b>${n}</b></p>
      <table class="tp"><tr><th>邮箱</th><th>注册时间</th><th>角色</th><th>状态</th><th>操作</th></tr><tbody id="rows"></tbody></table>
      <p id="msg" class="msg err"></p></div>
      <script>
      function load(){
        fetch('/admin/users').then(function(r){return r.json()}).then(function(d){
          var h='';var t;
          d.forEach(function(u){
            t=new Date(u.created*1000).toLocaleString('zh-CN');
            var roleBtn = u.role!=='admin' ? '<button class="btn-sm" data-em="'+u.email+'" data-a="role">设管理员</button> ' : '';
            var stBtn = '<button class="btn-sm" data-em="'+u.email+'" data-a="'+(u.status==='banned'?'unban':'ban')+'">'+(u.status==='banned'?'解封':'封禁')+'</button> ';
            var delBtn = '<button class="btn-sm" data-em="'+u.email+'" data-a="delete">删除</button>';
            h += '<tr><td>'+u.email+'</td><td>'+t+'</td><td class="'+(u.role==='admin'?'adm':'usr')+'">'+u.role+'</td><td>'+u.status+'</td><td>'+roleBtn+stBtn+delBtn+'</td></tr>';
          });
          document.getElementById('rows').innerHTML=h;
          document.querySelectorAll('#rows button').forEach(function(b){ b.onclick=function(){act(b.getAttribute('data-em'),b.getAttribute('data-a'))}; });
        }).catch(function(e){var m=document.getElementById('msg');m.textContent='加载失败';m.style.color='#dc2626'});
      }
      function act(em,a){
        if(a==='delete' && !confirm('确认删除 '+em+'？')) return;
        fetch('/admin/users',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'email='+encodeURIComponent(em)+'&action='+a})
          .then(function(r){return r.text()}).then(function(t){var m=document.getElementById('msg');m.textContent=t;m.style.color='#16a34a';load()});
      }
      load();</script></body></html>`));
  }
  if (req.method === 'GET' && p === '/admin/users') {
    const s = getSession(req); if (!s) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end('[]'); }
    const u = getUser.get(s.email); if (!u || u.role !== 'admin') { res.writeHead(403, { 'Content-Type': 'application/json' }); return res.end('[]'); }
    const rows = listUsers.all().map(r => ({ email: r.email, created: Math.floor((r.created || 0) / 1000), role: r.role, status: r.status }));
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' }); return res.end(JSON.stringify(rows));
  }
  if (req.method === 'POST' && p === '/admin/users') {
    const s = getSession(req); if (!s) { res.writeHead(401, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('未登录'); }
    const me = getUser.get(s.email); if (!me || me.role !== 'admin') { res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('403 无权限'); }
    const f = parseForm(await readBody(req));
    const email = (f.email || '').toLowerCase(); const action = f.action;
    if (!getUser.get(email)) { res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('用户不存在'); }
    if (email === ADMIN_EMAIL) { res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('最高管理员账号不可被操作'); }
    if (email === me.email && action !== 'role') { res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('不能对自己操作'); }
    if (action === 'ban') setStatus.run('banned', email);
    else if (action === 'unban') setStatus.run('active', email);
    else if (action === 'delete') delUser.run(email);
    else if (action === 'role') { const t = getUser.get(email); setRole.run(t.role === 'admin' ? 'user' : 'admin', email); }
    else { res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('未知操作'); }
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('操作成功');
  }

  res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html('404', '<div class="card"><h1>404</h1><p>页面不存在</p><a class="link" href="/">返回</a></div>'));
});

server.listen(PORT, () => console.log('App listening on :' + PORT));
