// server.js —— wuchenyun.top 多模块平台 P1（Express + SQLite + 邮箱验证码登录）
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const nodemailer = require('nodemailer');
const { db, stmts } = require('./db');
const { layout } = require('./layout');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase();
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ---------- 邮件验证码 / SMTP ----------
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST || '',
  port: Number(process.env.SMTP_PORT || 465),
  secure: Number(process.env.SMTP_PORT || 465) === 465,
  auth: { user: process.env.SMTP_USER || '', pass: process.env.SMTP_PASS || '' },
});
const MAIL_FROM = process.env.SMTP_FROM || process.env.SMTP_USER || '';

const emailCodes = {};
const CODE_LIFE = 5 * 60 * 1000;
function sendCode(email) {
  const code = String(crypto.randomInt(100000, 1000000));
  emailCodes[email] = { code, exp: Date.now() + CODE_LIFE };
  const txt = `【wuchenyun.top】你的登录验证码是 ${code}，5 分钟内有效。若非本人操作请忽略。`;
  return mailer.sendMail({ from: MAIL_FROM, to: email, subject: 'wuchenyun.top 登录验证码', text: txt });
}

// ---------- 会话（HMAC 签名 Cookie，3 天滑动） ----------
const SESSION_MS = 3 * 24 * 3600 * 1000;
const b64url = buf => Buffer.from(buf).toString('base64url');
const signHmac = p => crypto.createHmac('sha256', SESSION_SECRET).update(p).digest('base64url');
const createSession = email => { const p = b64url(JSON.stringify({ email, exp: Date.now() + SESSION_MS })); return p + '.' + signHmac(p); };
function getSession(req) {
  const t = getCookie(req); if (!t) return null;
  const i = t.lastIndexOf('.'); if (i < 0) return null;
  const p = t.slice(0, i), s = t.slice(i + 1);
  if (s.length !== signHmac(p).length) return null;
  try { if (!crypto.timingSafeEqual(Buffer.from(s), Buffer.from(signHmac(p)))) return null;
    const d = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (d && d.exp > Date.now()) return { email: d.email };
  } catch (e) {}
  return null;
}
function setCookie(res, tok) { res.setHeader('Set-Cookie', `sid=${tok}; HttpOnly; Path=/; Max-Age=${Math.floor(SESSION_MS / 1000)}`); }
function clearCookie(res) { res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0'); }
function getCookie(req) { const c = req.headers.cookie || ''; const m = c.match(/(?:^|;\s*)sid=([^;]+)/); return m ? m[1] : null; }

// ---------- 中间件 ----------
function requireUser(req, res, next) {
  const s = getSession(req); if (!s) return res.redirect('/');
  const u = stmts.getUser.get(s.email);
  if (!u || u.status === 'banned') { clearCookie(res); return res.redirect('/'); }
  setCookie(res, createSession(s.email));
  req.user = u; next();
}
function requireAdmin(req, res, next) {
  const s = getSession(req); if (!s) return res.redirect('/');
  const u = stmts.getUser.get(s.email);
  if (!u || u.role !== 'admin') return res.status(403).type('text/plain').send('403 无权限');
  setCookie(res, createSession(s.email));
  req.user = u; next();
}

// ---------- 登录页 ----------
function authPage(msg, err) {
  const m = msg ? `<div class="text-green-600 text-sm mt-3">${msg}</div>` : err ? `<div class="text-red-600 text-sm mt-3">${err}</div>` : '';
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>登录 · wuchenyun</title><script src="https://cdn.tailwindcss.com"></script></head>
  <body class="bg-gray-50 min-h-screen flex items-center justify-center">
  <div class="bg-white p-8 rounded-2xl shadow-sm w-full max-w-sm">
    <h1 class="text-xl font-bold">wuchenyun.top</h1>
    <h2 class="text-gray-500 text-sm mb-6">邮箱验证码登录</h2>
    ${m}
    <label class="text-sm text-gray-600 block mb-1 mt-4">邮箱</label>
    <div class="flex gap-2"><input id="email" type="email" placeholder="you@example.com" class="flex-1 border rounded-lg px-3 py-2 text-sm">
      <button onclick="send()" class="bg-blue-500 text-white rounded-lg px-3 text-sm">获取验证码</button></div>
    <label class="text-sm text-gray-600 block mb-1 mt-3">验证码</label>
    <input id="code" type="text" placeholder="6 位验证码" class="w-full border rounded-lg px-3 py-2 text-sm">
    <button onclick="login()" class="w-full bg-blue-600 text-white rounded-lg py-2.5 mt-5 text-sm">登录</button>
    <p id="hint" class="text-sm mt-3"></p>
  </div>
  <script>
  async function send(){const em=document.getElementById('email').value,h=document.getElementById('hint');
    if(!em||!em.includes('@')){h.textContent='请输入正确邮箱';h.className='text-sm mt-3 text-red-600';return}
    h.textContent='发送中...';h.className='text-sm mt-3';const r=await fetch('/send-code',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'email='+encodeURIComponent(em)});
    const t=await r.text();h.textContent=t;h.className='text-sm mt-3 '+(r.ok?'text-green-600':'text-red-600');}
  async function login(){const em=document.getElementById('email').value,c=document.getElementById('code').value,h=document.getElementById('hint');
    const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'email='+encodeURIComponent(em)+'&code='+encodeURIComponent(c)});
    if(r.redirected){location.href=r.url}else{const t=await r.text();h.textContent=t;h.className='text-sm mt-3 text-red-600';}}
  </script></body></html>`;
}

// ---------- 认证路由 ----------
app.get(['/', '/login'], (req, res) => {
  const s = getSession(req);
  if (s) { const u = stmts.getUser.get(s.email); return res.redirect(u && u.role === 'admin' ? '/admin' : '/app'); }
  res.type('html').send(authPage());
});
app.post('/send-code', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.type('text/plain').send('邮箱格式不对');
  const rec = stmts.getUser.get(email);
  if (rec && rec.status === 'banned') return res.type('text/plain').send('该账号已被封禁');
  try { await sendCode(email); res.type('text/plain').send('验证码已发送，请查收邮箱'); }
  catch (e) { res.type('text/plain').send('发送失败，请检查邮件配置'); }
});
app.post('/login', (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase(), code = (req.body.code || '').trim();
  const rec = emailCodes[email];
  if (!rec || rec.exp < Date.now() || rec.code !== code) return res.type('text/plain').send('验证码错误或已过期');
  delete emailCodes[email];
  let u = stmts.getUser.get(email);
  if (!u) { stmts.insUser.run(email, Date.now(), email === ADMIN_EMAIL ? 'admin' : 'user'); u = stmts.getUser.get(email); }
  else if (email === ADMIN_EMAIL && u.role !== 'admin') { stmts.setRole.run('admin', email); u = stmts.getUser.get(email); }
  if (!u) return res.type('text/plain').send('注册失败，请重试');
  if (u.status === 'banned') return res.type('text/plain').send('该账号已被封禁');
  setCookie(res, createSession(email));
  res.redirect('/app');
});
app.get('/logout', (req, res) => { clearCookie(res); res.redirect('/'); });

// ---------- 用户模块（P1 骨架页）----------
function stubPage(active, title, desc, userEmail, role) {
  return layout({ title, userEmail, role, active, content: `
    <h1 class="text-2xl font-bold mb-2">${title}</h1>
    <p class="text-gray-500 mb-6">${desc}</p>
    <div class="border-2 border-dashed border-gray-200 rounded-xl p-10 text-center text-gray-400 bg-white">功能建设中（P1 框架已就绪）</div>` });
}

app.get('/app', requireUser, (req, res) => {
  const cards = [
    { icon: '🛒', t: '我的商品监控', d: '多平台比价 + 每日报价 + 目标价提醒', href: '/app/monitor', live: true },
    { icon: '⭐', t: '我的收藏', d: '收藏商品 / 批量加入监控', href: '/app/favorites' },
    { icon: '🔗', t: '我的链接', d: '保存常用链接', href: '/app/links' },
    { icon: '📊', t: '我的数据', d: '价格趋势 / 监控统计', href: '/app/data' },
    { icon: '⚙️', t: '设置', d: '偏好 / 监控上限等', href: '/app/settings' },
  ];
  const body = cards.map(c => `<a href="${c.href}" class="block bg-white rounded-xl p-5 border border-gray-100 hover:shadow-md transition">
    <div class="text-2xl mb-2">${c.icon}</div><div class="font-semibold">${c.t}</div>
    <div class="text-xs text-gray-500 mt-1">${c.d}</div>
    ${c.live ? '<span class="inline-block mt-2 text-[11px] bg-blue-50 text-blue-600 px-2 py-0.5 rounded">可用</span>' : '<span class="inline-block mt-2 text-[11px] bg-gray-100 text-gray-400 px-2 py-0.5 rounded">即将上线</span>'}
  </a>`).join('');
  const s = layout({ title: '我的工具', userEmail: req.user.email, role: req.user.role, active: 'tools', content: `
    <h1 class="text-2xl font-bold mb-2">我的工具</h1>
    <p class="text-gray-500 mb-6">选择一个工具开始使用</p>
    <div class="grid sm:grid-cols-2 gap-4">${body}</div>` });
  res.type('html').send(s);
});
const USER_MODULES = {
  profile:   ['个人资料', '登录账号与个人资料管理'],
  monitor:   ['我的商品监控', '多平台比价、收藏、每日报价、目标价提醒'],
  favorites: ['我的收藏', '收藏的商品，可批量加入监控'],
  links:     ['我的链接', '收藏的链接'],
  data:      ['我的数据', '价格曲线与监控统计'],
  settings:  ['设置', '站点偏好与监控上限'],
};
Object.entries(USER_MODULES).forEach(([key, [t, d]]) => {
  app.get('/app/' + key, requireUser, (req, res) => {
    res.type('html').send(stubPage(key, t, d, req.user.email, req.user.role));
  });
});

// ---------- 管理员 ----------
app.get('/admin', requireAdmin, (req, res) => {
  const n = stmts.countUsers.get().n;
  const rows = stmts.listUsers.all().map(r => ({ email: r.email, created: new Date(r.created * 1000).toLocaleString('zh-CN'), role: r.role, status: r.status, super: r.email === ADMIN_EMAIL }));
  const trs = rows.map(u => `<tr class="border-b border-gray-100">
    <td class="py-2 px-2">${u.email}</td><td class="py-2 px-2 text-gray-500 text-sm">${u.created}</td>
    <td class="py-2 px-2 ${u.role === 'admin' ? 'text-red-600' : 'text-green-600'}">${u.role}${u.super ? ' ⭐' : ''}</td>
    <td class="py-2 px-2">${u.status}</td>
    <td class="py-2 px-2 text-xs">${u.super ? '—' : `<button class="btn" data-em="${u.email}" data-a="role">角色</button> <button class="btn" data-em="${u.email}" data-a="${u.status === 'banned' ? 'unban' : 'ban'}">${u.status === 'banned' ? '解封' : '封禁'}</button> <button class="btn text-red-500" data-em="${u.email}" data-a="delete">删除</button>`}</td>
  </tr>`).join('');
  res.type('html').send(layout({ title: '管理后台', userEmail: req.user.email, role: req.user.role, active: 'admin', content: `
    <div class="flex items-center justify-between mb-6"><h1 class="text-2xl font-bold">管理后台</h1>
      <a href="/admin/monitor" class="text-sm text-blue-600">📈 网站监控</a></div>
    <div class="bg-white rounded-xl border border-gray-100 p-6">
      <p class="text-gray-500 mb-4">总用户数：<b>${n}</b></p>
      <table class="w-full text-left"><thead><tr class="text-gray-500 text-sm"><th class="py-2">邮箱</th><th>注册时间</th><th>角色</th><th>状态</th><th>操作</th></tr></thead>
      <tbody id="rows">${trs}</tbody></table>
      <p id="msg" class="text-sm mt-3"></p></div>
    <script>
    document.querySelectorAll('.btn').forEach(b=>b.onclick=()=>{const em=b.dataset.em,a=b.dataset.a;
      if(a==='delete'&&!confirm('确认删除 '+em+'？'))return;
      fetch('/admin/users',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'email='+encodeURIComponent(em)+'&action='+a})
      .then(r=>r.text()).then(t=>{document.getElementById('msg').textContent=t;setTimeout(()=>location.reload(),600)})});
    </script>` }) );
});
app.get('/admin/monitor', requireAdmin, (req, res) => {
  res.type('html').send(layout({ title: '网站监控', userEmail: req.user.email, role: req.user.role, active: 'admin', content: `
    <h1 class="text-2xl font-bold mb-6">📈 网站监控</h1>
    <div class="grid sm:grid-cols-3 gap-4">
      <div class="bg-white rounded-xl border border-gray-100 p-5"><div class="text-sm text-gray-500">CPU</div><div class="text-xl font-bold">—</div></div>
      <div class="bg-white rounded-xl border border-gray-100 p-5"><div class="text-sm text-gray-500">内存</div><div class="text-xl font-bold">—</div></div>
      <div class="bg-white rounded-xl border border-gray-100 p-5"><div class="text-sm text-gray-500">负载</div><div class="text-xl font-bold">—</div></div>
    </div>
    <p class="text-gray-400 text-sm mt-6">系统/服务/抓取监测将在 P4 落地，当前为框架占位。</p>` }) );
});
app.get('/admin/users', requireAdmin, (req, res) => {
  const rows = stmts.listUsers.all().map(r => ({ email: r.email, created: Math.floor((r.created || 0) / 1000), role: r.role, status: r.status, super: r.email === ADMIN_EMAIL }));
  res.json(rows);
});
app.post('/admin/users', requireAdmin, (req, res) => {
  const email = (req.body.email || '').toLowerCase(), action = req.body.action;
  if (!stmts.getUser.get(email)) return res.type('text/plain').send('用户不存在');
  if (email === ADMIN_EMAIL) return res.type('text/plain').send('最高管理员账号不可被操作');
  if (email === req.user.email && action !== 'role') return res.type('text/plain').send('不能对自己操作');
  if (action === 'ban') stmts.setStatus.run('banned', email);
  else if (action === 'unban') stmts.setStatus.run('active', email);
  else if (action === 'delete') stmts.delUser.run(email);
  else if (action === 'role') { const t = stmts.getUser.get(email); stmts.setRole.run(t.role === 'admin' ? 'user' : 'admin', email); }
  else return res.type('text/plain').send('未知操作');
  res.type('text/plain').send('操作成功');
});

// ---------- 404 ----------
app.use((req, res) => res.status(404).type('text/plain').send('404 页面不存在'));

app.listen(PORT, () => console.log('App listening on :' + PORT));
