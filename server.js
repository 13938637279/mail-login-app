// server.js —— wuchenyun.top 多模块平台 P1/P2（Express + SQLite + 邮箱验证码登录）
const express = require('express');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { db, stmts, p2 } = require('./db');
const { layout } = require('./layout');
const { searchAll } = require('./adapters');

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
      <button id="sendBtn" onclick="send()" class="bg-blue-500 text-white rounded-lg px-3 text-sm">获取验证码</button></div>
    <label class="text-sm text-gray-600 block mb-1 mt-3">验证码</label>
    <input id="code" type="text" placeholder="6 位验证码" class="w-full border rounded-lg px-3 py-2 text-sm">
    <button onclick="login()" class="w-full bg-blue-600 text-white rounded-lg py-2.5 mt-5 text-sm">登录</button>
    <p id="hint" class="text-sm mt-3"></p>
  </div>
  <script>
  let cd=0;
  async function send(){const em=document.getElementById('email').value,h=document.getElementById('hint'),btn=document.getElementById('sendBtn');
    if(!em||!em.includes('@')){h.textContent='请输入正确邮箱';h.className='text-sm mt-3 text-red-600';return}
    btn.disabled=true;btn.style.opacity='0.5';btn.classList.add('bg-gray-300');btn.classList.remove('bg-blue-500');btn.textContent='发送中...';
    h.textContent='发送中...';h.className='text-sm mt-3';
    const r=await fetch('/send-code',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'email='+encodeURIComponent(em)});
    const t=await r.text();h.textContent=t;h.className='text-sm mt-3 '+(r.ok?'text-green-600':'text-red-600');
    if(t.indexOf('已发送')>=0){
      cd=60;btn.textContent=cd+'s';
      const iv=setInterval(()=>{btn.textContent=(--cd)+'s';if(cd<=0){clearInterval(iv);btn.disabled=false;btn.style.opacity='1';btn.classList.add('bg-blue-500');btn.classList.remove('bg-gray-300');btn.textContent='重发';}},1000);
    }else{btn.disabled=false;btn.style.opacity='1';btn.classList.remove('bg-gray-300');btn.classList.add('bg-blue-500');btn.textContent='获取验证码';}}
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

// ---------- 拼多多 OAuth/API 回调（独立于本站登录，public） ----------
// PDD 授权/回调会带 code,state 等参数；本站只需接收、记录、返回成功页。
// 与本站邮箱登录完全分开，不混用 session。
app.get('/api/pdd/callback', pddCallback);
app.post('/api/pdd/callback', pddCallback);
function pddCallback(req, res) {
  const q = req.query || {}, b = (typeof req.body === 'object' ? req.body : {});
  const code = (q.code || b.code || '').toString();
  const state = (q.state || b.state || '').toString();
  const raw = JSON.stringify({ query: q, body: b });
  try { p2.addOauthCallback.run('pdd', code.slice(0, 200), state.slice(0, 200), raw.slice(0, 4000), Date.now()); } catch (e) {}
  // TODO(接入时)：1) 若开 CSRF，校验 state 是否匹配会话里存的随机器 2) 有 code 则用 client_id/secret 换 access_token
  //             3) 查订单/商品信息等。以下为占位成功页。
  const hasParams = code || state;
  res.type('html').send(`<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>回调 · wuchenyun</title><script src="https://cdn.tailwindcss.com"></script></head>
  <body class="bg-gray-50 min-h-screen flex items-center justify-center">
  <div class="bg-white p-8 rounded-2xl shadow-sm w-full max-w-sm text-center">
    <div class="text-3xl mb-2">${hasParams ? '✅' : '⚠️'}</div>
    <h1 class="text-lg font-semibold">拼多多回调</h1>
    <p class="text-sm text-gray-500 mt-2">${hasParams ? '已收到授权回调并记录。' : '未收到回调参数。'}</p>
    <p class="text-xs text-gray-400 mt-4">code: ${code ? '已收到' : '无'} · state: ${state ? '已收到' : '无'}</p>
    <a href="/" class="inline-block mt-5 text-sm text-blue-600">返回首页</a>
  </div></body></html>`);
}

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
  links:     ['我的链接', '收藏的链接'],
  settings:  ['设置', '站点偏好与监控上限'],
};
Object.entries(USER_MODULES).forEach(([key, [t, d]]) => {
  app.get('/app/' + key, requireUser, (req, res) => {
    res.type('html').send(stubPage(key, t, d, req.user.email, req.user.role));
  });
});

// ============ P2：比价/监控 ============
const MAX_MONITORS = Number(process.env.MAX_MONITORS || 50);
function today() { const d = new Date(); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); }
// 商品入库 + 记录一次“今日价”（演示源把搜索价当今日真实价）
function ensureProduct(platform, sku, info, price) {
  p2.upsertProduct.run(platform, sku, info.title, info.img || '', info.url || '', price, Date.now(), 'fresh');
  const prod = p2.getProductBySku.get(platform, sku);
  p2.insertPricePoint.run(prod.id, today(), price, 'fresh');
  return prod;
}

// —— 搜索 ——
app.get('/api/search', requireUser, async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json({ results: [] });
  const found = await searchAll(q);
  const results = found.map(r => {
    const prod = ensureProduct(r.platform, r.sku, r, r.price);
    return { id: prod.id, platform: prod.platform, sku: prod.sku, title: prod.title, img: prod.img, url: prod.url,
      price: prod.last_price, monitored: !!p2.isMonitor.get(req.user.email, prod.id), favorited: !!p2.isFavorite.get(req.user.email, prod.id) };
  });
  res.json({ results });
});

// —— 收藏 ——
app.post('/api/favorite', requireUser, (req, res) => {
  const prod = p2.getProductBySku.get(req.body.platform, req.body.sku);
  if (!prod) return res.status(404).json({ ok: false, error: '商品不存在' });
  p2.addFavorite.run(req.user.email, prod.id, Date.now());
  res.json({ ok: true });
});
app.post('/api/unfavorite', requireUser, (req, res) => {
  const prod = p2.getProductBySku.get(req.body.platform, req.body.sku);
  if (prod) p2.removeFavorite.run(req.user.email, prod.id);
  res.json({ ok: true });
});

// —— 监控 ——
app.post('/api/monitor', requireUser, (req, res) => {
  const prod = p2.getProductBySku.get(req.body.platform, req.body.sku);
  if (!prod) return res.status(404).json({ ok: false, error: '商品不存在' });
  if (p2.countMonitorsByUser.get(req.user.email).n >= MAX_MONITORS) return res.status(400).json({ ok: false, error: '已达监控上限' });
  p2.addMonitor.run(req.user.email, prod.id, req.body.target_price || null, Date.now());
  res.json({ ok: true });
});
app.post('/api/unmonitor', requireUser, (req, res) => {
  const prod = p2.getProductBySku.get(req.body.platform, req.body.sku);
  if (prod) p2.removeMonitor.run(req.user.email, prod.id);
  res.json({ ok: true });
});
app.post('/api/monitor/batch', requireUser, (req, res) => {
  const items = (req.body.items || []).slice(0, 5);
  const n = p2.countMonitorsByUser.get(req.user.email).n;
  let added = 0, dup = 0, skipped = 0;
  for (const it of items) {
    if (n + added >= MAX_MONITORS) { skipped++; continue; }
    const prod = p2.getProductBySku.get(it.platform, it.sku);
    if (!prod) { skipped++; continue; }
    if (p2.isMonitor.get(req.user.email, prod.id)) { dup++; continue; }
    p2.addMonitor.run(req.user.email, prod.id, it.target_price || null, Date.now());
    added++;
  }
  res.json({ ok: true, added, dup, skipped });
});
app.get('/api/monitors', requireUser, (req, res) => {
  const items = p2.listMonitors.all(req.user.email).map(r => ({ id: r.product_id, platform: r.platform, sku: r.sku, title: r.title, img: r.img, url: r.url, last_price: r.last_price, status: r.status, target_price: r.target_price, observed_at: r.observed_at }));
  res.json({ items });
});
app.get('/api/favorites', requireUser, (req, res) => {
  const items = p2.listFavorites.all(req.user.email).map(r => ({ id: r.product_id, platform: r.platform, sku: r.sku, title: r.title, img: r.img, url: r.url, last_price: r.last_price, status: r.status }));
  res.json({ items });
});

// —— 我的商品监控 页面 ——
app.get('/app/monitor', requireUser, (req, res) => {
  const s = layout({ title: '我的商品监控', userEmail: req.user.email, role: req.user.role, active: 'monitor', content: `
  <div x-data="monitorApp()" x-init="init()">
    <h1 class="text-2xl font-bold mb-2">我的商品监控</h1>
    <p class="text-gray-500 mb-5">输入商品名搜索，多平台比价。搜到的商品可「收藏 / 加入监控」。</p>
    <div class="flex gap-2 mb-5">
      <input x-model="q" @keydown.enter="search()" placeholder="输入商品名，如 iPhone / 华为" class="flex-1 border rounded-lg px-3 py-2 text-sm">
      <button @click="search()" class="bg-blue-600 text-white rounded-lg px-4 text-sm">搜索</button>
    </div>
    <p x-show="loading" class="text-gray-400 text-sm mb-3">搜索中...</p>

    <template x-for="r in results" :key="r.sku">
      <div class="bg-white border border-gray-100 rounded-xl p-4 mb-3">
        <div class="flex items-start justify-between gap-3">
          <div>
            <div class="font-semibold" x-text="r.title"></div>
            <div class="text-xs text-gray-400 mt-1" x-text="'来源 ' + (r.platform)"></div>
          </div>
          <div class="text-right">
            <div class="text-xl font-bold" x-text="'¥' + r.price"></div>
            <div class="text-[11px] text-gray-400">今日价</div>
          </div>
        </div>
        <div class="flex gap-2 mt-3">
          <button @click="monitor(r)"
            class="px-3 py-1.5 text-xs rounded-lg" :class="r.monitored ? 'bg-gray-100 text-gray-400' : 'bg-blue-50 text-blue-600'"
            x-text="r.monitored ? '已监控' : '加入监控'"></button>
          <button @click="favorite(r)"
            class="px-3 py-1.5 text-xs rounded-lg" :class="r.favorited ? 'bg-amber-100 text-amber-600' : 'bg-gray-100 text-gray-600'"
            x-text="r.favorited ? '已收藏' : '收藏'"></button>
        </div>
      </div>
    </template>
    <p x-show="!loading && results.length===0 && searched" class="text-gray-400 text-sm">没有结果。</p>

    <h2 class="text-lg font-semibold mt-8 mb-3">我的监控（<span x-text="monitors.length"></span>）</h2>
    <template x-for="m in monitors" :key="m.id">
      <div class="bg-white border border-gray-100 rounded-xl p-4 mb-2 flex items-center justify-between">
        <div>
          <div class="font-medium text-sm" x-text="m.title"></div>
          <div class="text-xs text-gray-400 mt-1">最新 <span x-text="m.last_price!=null ? '¥'+m.last_price : '—'"></span>
            <span class="ml-2" x-text="m.status==='stale' ? '（stale·参考）' : ''"></span></div>
        </div>
        <button @click="unmonitor(m)" class="text-xs text-red-500">移除</button>
      </div>
    </template>
    <p x-show="monitors.length===0" class="text-gray-400 text-sm">还没有监控的商品。</p>
  </div>
  <script>
  window.monitorApp = function(){ return {
    q:'', results:[], monitors:[], favorites:[], loading:false, searched:false,
    init(){ this.loadMonitors(); },
    async search(){
      this.loading=true; this.searched=true;
      const r = await fetch('/api/search?q='+encodeURIComponent(this.q));
      const d = await r.json(); this.results = d.results; this.loading=false;
    },
    async favorite(r){ await fetch(r.favorited?'/api/unfavorite':'/api/favorite',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({platform:r.platform,sku:r.sku})}); r.favorited=!r.favorited; },
    async monitor(r){ const resp=await fetch('/api/monitor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({platform:r.platform,sku:r.sku})}); const d=await resp.json(); if(d&&d.error){alert(d.error)} r.monitored=true; this.loadMonitors(); },
    async unmonitor(m){ await fetch('/api/unmonitor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({platform:m.platform,sku:m.sku})}); this.loadMonitors(); },
    async loadMonitors(){ const r=await fetch('/api/monitors'); const d=await r.json(); this.monitors=d.items; },
  } };
  </script>` });
  res.type('html').send(s);
});

// —— 价格点（仅允许查看自己监控/收藏的商品）——
app.get('/api/price-points', requireUser, (req, res) => {
  const id = Number(req.query.product_id);
  if (!id) return res.json({ points: [] });
  if (!p2.isMonitor.get(req.user.email, id) && !p2.isFavorite.get(req.user.email, id)) return res.status(403).json({ points: [] });
  const points = p2.listPricePoints.all(id).map(r => ({ date: r.date, price: r.price, status: r.status }));
  res.json({ points });
});

// —— 我的收藏 页面（批量加监控，至多5个）——
app.get('/app/favorites', requireUser, (req, res) => {
  const s = layout({ title: '我的收藏', userEmail: req.user.email, role: req.user.role, active: 'favorites', content: `
  <div x-data="favApp()" x-init="init()">
    <h1 class="text-2xl font-bold mb-2">我的收藏</h1>
    <p class="text-gray-500 mb-4">勾选收藏的商品，批量加入监控（至多 5 个）。</p>
    <div class="flex items-center justify-between mb-3">
      <span class="text-sm text-gray-500" x-text="'已选 ' + sel.length + '/5'"></span>
      <button @click="batch()" class="bg-blue-600 text-white rounded-lg px-4 py-2 text-sm">批量加入监控</button>
    </div>
    <p x-show="msg" x-text="msg" class="text-sm text-green-600 mb-3"></p>
    <template x-for="f in favs" :key="f.id">
      <div class="bg-white border border-gray-100 rounded-xl p-3 mb-2 flex items-center gap-3">
        <input type="checkbox" @change="toggle($event, f)">
        <div class="flex-1">
          <div class="font-medium text-sm" x-text="f.title"></div>
          <div class="text-xs text-gray-400">来源 <span x-text="f.platform"></span> · 最新 <span x-text="f.last_price!=null ? '¥'+f.last_price : '—'"></span></div>
        </div>
        <button @click="unfav(f)" class="text-xs text-red-500">移除</button>
      </div>
    </template>
    <p x-show="favs.length===0" class="text-gray-400 text-sm">还没有收藏。到「我的商品监控」搜索并点「收藏」。</p>
  </div>
  <script>
  window.favApp = function(){ return {
    favs:[], sel:[], msg:'',
    init(){ this.load(); },
    async load(){ const r=await fetch('/api/favorites'); this.favs=(await r.json()).items; },
    toggle(e,f){ if(e.target.checked){ if(this.sel.length>=5){ e.target.checked=false; alert('至多选 5 个'); return; } this.sel.push({platform:f.platform, sku:f.sku}); } else { this.sel=this.sel.filter(x=>!(x.platform===f.platform&&x.sku===f.sku)); } },
    async batch(){ if(!this.sel.length){ this.msg='请先勾选商品'; return; }
      const r=await fetch('/api/monitor/batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({items:this.sel})});
      const d=await r.json(); this.msg='新增 '+d.added+' 个，已在监控 '+d.dup+' 个，跳过 '+d.skipped+' 个'; this.sel=[]; document.querySelectorAll('input[type=checkbox]').forEach(c=>c.checked=false); },
    async unfav(f){ await fetch('/api/unfavorite',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({platform:f.platform,sku:f.sku})}); this.load(); },
  } };
  </script>` });
  res.type('html').send(s);
});

// —— 我的数据 页面（价格曲线）——
app.get('/app/data', requireUser, (req, res) => {
  const s = layout({ title: '我的数据', userEmail: req.user.email, role: req.user.role, active: 'data', content: `
  <div x-data="dataApp()" x-init="init()">
    <h1 class="text-2xl font-bold mb-2">我的数据</h1>
    <p class="text-gray-500 mb-4">选择一个监控中的商品，查看价格走势（近 30 天）。</p>
    <select x-model="pid" @change="load()" class="border rounded-lg px-3 py-2 text-sm mb-4">
      <option value="">-- 选择监控商品 --</option>
      <template x-for="m in monitors" :key="m.id"><option :value="m.id" x-text="m.title"></option></template>
    </select>
    <div id="chart-box" class="bg-white border border-gray-100 rounded-xl p-4"></div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/apexcharts"></script>
  <script>
  window.dataApp = function(){ return {
    monitors:[], pid:'',
    async init(){ const r=await fetch('/api/monitors'); this.monitors=(await r.json()).items; if(this.monitors.length){ this.pid=this.monitors[0].id; this.load(); } },
    async load(){ if(!this.pid) return; const r=await fetch('/api/price-points?product_id='+this.pid); const d=await r.json();
      const dates=d.points.map(p=>p.date), vals=d.points.map(p=>p.price);
      new ApexCharts(document.querySelector('#chart-box'),{ chart:{type:'line',height:300}, series:[{name:'价格',data:vals}], xaxis:{categories:dates}, stroke:{curve:'smooth'}, colors:['#3b82f6'] }).render(); },
  } };
  </script>` });
  res.type('html').send(s);
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
