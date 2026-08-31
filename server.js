// server.js —— wuchenyun.top 多模块平台 P1/P2（Express + SQLite + 邮箱验证码登录）
const express = require('express');
const crypto = require('crypto');
const os = require('os');
const nodemailer = require('nodemailer');
const { db, stmts, p2 } = require('./db');
const { layout } = require('./layout');
const { searchAll, getCurrentPrice } = require('./adapters');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase();
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.set('trust proxy', 1); // 服务器在 Cloudflare/反代后，信任 X-Forwarded-Proto 以判定是否 HTTPS

// ---------- 安全加固：HTML 转义 / 限流 / CSRF 防护 / 安全头 / HTTPS 跳转 ----------
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// 简易内存限流（固定窗口）。key 形如 'ip|email' 等。命中超限返回 true。
const rlMap = new Map();
function rateLimit(key, limit, windowMs) {
  const now = Date.now();
  let e = rlMap.get(key);
  if (!e || now - e.start > windowMs) { e = { start: now, count: 0 }; rlMap.set(key, e); }
  e.count++;
  return e.count > limit;
}
function rateLimited(key, limit, windowMs) { return rateLimit(key, limit, windowMs); }
// 定期清理过期的限流计数与过期验证码（防止内存无限增长）
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rlMap) { if (now - v.start > 5 * 60 * 1000) rlMap.delete(k); }
  for (const k of Object.keys(emailCodes)) { if (emailCodes[k].exp < now) delete emailCodes[k]; }
}, 60 * 1000).unref();

// 安全响应头（防点击劫持/嗅探/MIME 混淆）
function securityHeaders(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; " +
    "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; img-src 'self' data: https:; " +
    "connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
  );
  // 已判定为 HTTPS 时才发 HSTS（浏览器仅在 https 下识别）
  const https = req.secure || req.headers['x-forwarded-proto'] === 'https';
  if (https) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
}
// HTTPS 由 Cloudflare 边缘强制（推荐开启「Always Use HTTPS」）；此处不做应用层跳转，避免反代头误配导致重定向环路。
// CSRF 防护：非幂等请求若带 Origin/Referer，必须与站点同源（浏览器跨站 POST 会被拒），无形同源的客户端(服务器/curl)放行
function csrfGuard(req, res, next) {
  const m = req.method;
  if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return next();
  const host = req.headers.host;
  const origin = req.headers.origin, referer = req.headers.referer;
  if (!origin && !referer) return next(); // 非浏览器客户端（cron/curl/服务器间）无 Origin
  const src = origin || referer;
  try {
    if (new URL(src).host === host) return next();
  } catch (e) {}
  return res.status(403).type('text/plain').send('403 Cross-origin request blocked');
}
app.use(securityHeaders);
app.use(csrfGuard);

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
  emailCodes[email] = { code, exp: Date.now() + CODE_LIFE, tries: 0 };
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
function setCookie(res, tok) {
  // 无条件 Secure（fail-closed）：后端 HTTPS 由 Cloudflare 边缘/反代终结，浏览器↔CF 恒为 https，
  // 故 http 直连拿不到可用会话，杜绝明文嗅探会话；配合 CF「Always Use HTTPS」自动升级 http→https。
  res.setHeader('Set-Cookie', `sid=${tok}; HttpOnly; Path=/; Max-Age=${Math.floor(SESSION_MS / 1000)}; SameSite=Lax; Secure`);
}
function clearCookie(res) { res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure'); }
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

// ---------- 密码哈希（scrypt） ----------
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const h = crypto.scryptSync(String(pw), salt, 32).toString('hex');
  return salt + ':' + h;
}
function verifyPw(pw, stored) {
  if (!stored || stored.indexOf(':') < 0) return false;
  const [salt, h] = stored.split(':');
  try {
    const calc = crypto.scryptSync(String(pw), salt, 32).toString('hex');
    return calc.length === h.length && crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(h));
  } catch (e) { return false; }
}

// ---------- 登录页（密码 / 验证码 二选一） ----------
function authPage(msg, err) {
  const m = msg ? `<div class="text-green-600 text-sm mt-3">${msg}</div>` : err ? `<div class="text-red-600 text-sm mt-3">${err}</div>` : '';
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>登录 · wuchenyun</title><script src="https://cdn.tailwindcss.com"></script></head>
  <body class="bg-gray-50 min-h-screen flex items-center justify-center">
  <div class="bg-white p-8 rounded-2xl shadow-sm w-full max-w-sm">
    <h1 class="text-xl font-bold">wuchenyun.top</h1>
    <h2 class="text-gray-500 text-sm mb-6">登录</h2>
    ${m}
    <div class="flex gap-2 mb-5">
      <button id="tabCode" onclick="tab('code')" class="flex-1 py-2 text-sm rounded-lg bg-blue-50 text-blue-600 font-semibold">验证码登录</button>
      <button id="tabPwd" onclick="tab('pwd')" class="flex-1 py-2 text-sm rounded-lg text-gray-500">密码登录</button>
    </div>

    <!-- 验证码登录 -->
    <div id="panelCode">
      <label class="text-sm text-gray-600 block mb-1">邮箱</label>
      <div class="flex gap-2 mb-3"><input id="email" type="email" placeholder="you@example.com" class="flex-1 border rounded-lg px-3 py-2 text-sm">
        <button id="sendBtn" onclick="send()" class="bg-blue-500 text-white rounded-lg px-3 text-sm">获取验证码</button></div>
      <label class="text-sm text-gray-600 block mb-1">验证码</label>
      <input id="code" type="text" placeholder="6 位验证码" class="w-full border rounded-lg px-3 py-2 text-sm">
      <div id="regBox" style="display:none;margin-top:12px">
        <label class="text-sm text-gray-600 block mb-1">设置密码（新账号）</label>
        <input id="pw1" type="password" placeholder="密码" class="w-full border rounded-lg px-3 py-2 text-sm mb-2">
        <input id="pw2" type="password" placeholder="确认密码" class="w-full border rounded-lg px-3 py-2 text-sm">
      </div>
      <button id="codeLoginBtn" onclick="codeBtn()" class="w-full bg-blue-600 text-white rounded-lg py-2.5 mt-4 text-sm">登录</button>
    </div>

    <!-- 密码登录 -->
    <div id="panelPwd" style="display:none">
      <label class="text-sm text-gray-600 block mb-1">邮箱</label>
      <input id="pemail" type="email" placeholder="you@example.com" class="w-full border rounded-lg px-3 py-2 text-sm">
      <label class="text-sm text-gray-600 block mb-1 mt-3">密码</label>
      <input id="ppwd" type="password" placeholder="密码" class="w-full border rounded-lg px-3 py-2 text-sm">
      <button onclick="loginPwd()" class="w-full bg-blue-600 text-white rounded-lg py-2.5 mt-4 text-sm">登录</button>
    </div>

    <p id="hint" class="text-sm mt-3"></p>
  </div>
  <script>
  let cd=0, needReg=false;
  function tab(m){
    document.getElementById('tabCode').className = 'flex-1 py-2 text-sm rounded-lg ' + (m==='code'?'bg-blue-50 text-blue-600 font-semibold':'text-gray-500');
    document.getElementById('tabPwd').className = 'flex-1 py-2 text-sm rounded-lg ' + (m==='pwd'?'bg-blue-50 text-blue-600 font-semibold':'text-gray-500');
    document.getElementById('panelCode').style.display = m==='code'?'':'none';
    document.getElementById('panelPwd').style.display = m==='pwd'?'':'none';
  }
  function hint(t, ok){ const h=document.getElementById('hint'); h.textContent=t; h.className='text-sm mt-3 '+(ok?'text-green-600':'text-red-600'); }
  async function send(){const em=document.getElementById('email').value,h=document.getElementById('hint'),btn=document.getElementById('sendBtn');
    if(!em||!em.includes('@')){hint('请输入正确邮箱',false);return}
    btn.disabled=true;btn.style.opacity='0.5';btn.classList.add('bg-gray-300');btn.classList.remove('bg-blue-500');btn.textContent='发送中...';
    const r=await fetch('/send-code',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'email='+encodeURIComponent(em)});
    const t=await r.text();hint(t, r.ok);
    if(t.indexOf('已发送')>=0){ cd=60;btn.textContent=cd+'s';
      const iv=setInterval(()=>{btn.textContent=(--cd)+'s';if(cd<=0){clearInterval(iv);btn.disabled=false;btn.style.opacity='1';btn.classList.add('bg-blue-500');btn.classList.remove('bg-gray-300');btn.textContent='重发';}},1000);
    }else{btn.disabled=false;btn.style.opacity='1';btn.classList.remove('bg-gray-300');btn.classList.add('bg-blue-500');btn.textContent='获取验证码';}}
  async function codeBtn(){ if(needReg){ doRegister(); } else { loginCode(); } }
  async function loginCode(){
    const em=document.getElementById('email').value, c=document.getElementById('code').value;
    const r=await fetch('/login-code',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'email='+encodeURIComponent(em)+'&code='+encodeURIComponent(c)});
    if(r.redirected){ location.href=r.url; return; }
    let d; try{ d=await r.json(); }catch(e){ d = {}; }
    if(d && d.register){ needReg=true; document.getElementById('regBox').style.display='block';
      document.getElementById('codeLoginBtn').textContent='完成注册'; hint('新账号：请设置密码后点“完成注册”。', false); return; }
    const t = await r.text(); hint(t, false);
  }
  async function doRegister(){
    const em=document.getElementById('email').value, c=document.getElementById('code').value,
      p1=document.getElementById('pw1').value, p2=document.getElementById('pw2').value;
    if(p1.length<6){ hint('密码至少 6 位。', false); return; }
    if(p1!==p2){ hint('两次密码不一致。', false); return; }
    const r=await fetch('/register',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'email='+encodeURIComponent(em)+'&code='+encodeURIComponent(c)+'&password='+encodeURIComponent(p1)});
    if(r.redirected){ location.href=r.url; return; }
    const t=await r.text(); hint(t, false);
  }
  async function loginPwd(){
    const em=document.getElementById('pemail').value, pp=document.getElementById('ppwd').value;
    const r=await fetch('/login-password',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'email='+encodeURIComponent(em)+'&password='+encodeURIComponent(pp)});
    if(r.redirected){ location.href=r.url; return; }
    const t=await r.text(); hint(t, false);
  }
  </script></body></html>`;
}

// ---------- 认证路由 ----------
app.get(['/', '/login'], (req, res) => {
  const s = getSession(req);
  if (s) { return res.redirect('/app'); }
  res.type('html').send(authPage());
});
// 验证码：错误次数上限，超限作废需重新获取（防 6 位枚举爆破）
const CODE_MAX_TRIES = 5;
// 校验验证码：count 为 true 时才一次性作废（成功即删）；否则仅校验（注册前保留供 /register 复用）
function verifyCode(email, code, consume) {
  const rec = emailCodes[email];
  if (!rec || rec.exp < Date.now()) { if (rec) delete emailCodes[email]; return false; }
  if (rec.tries >= CODE_MAX_TRIES) { delete emailCodes[email]; return false; }
  if (rec.code !== code) { rec.tries++; if (rec.tries >= CODE_MAX_TRIES) delete emailCodes[email]; return false; }
  if (consume) delete emailCodes[email]; // 一次一用
  return true;
}
app.post('/send-code', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.type('text/plain').send('邮箱格式不对');
  const ip = req.ip || req.connection.remoteAddress || '';
  if (rateLimited('sendcode|email|' + email, 1, 60 * 1000)) return res.type('text/plain').send('发送过于频繁，请稍后再试');
  if (rateLimited('sendcode|ip|' + ip, 10, 15 * 60 * 1000)) return res.type('text/plain').send('操作过于频繁，请稍后再试');
  const rec = stmts.getUser.get(email);
  if (rec && rec.status === 'banned') return res.type('text/plain').send('发送失败，请检查邮箱'); // 不泄露封禁状态
  try { await sendCode(email); res.type('text/plain').send('验证码已发送，请查收邮箱'); }
  catch (e) { res.type('text/plain').send('发送失败，请检查邮件配置'); }
});
// 验证码登录：已注册→登录；未注册→返回 {register:true}，前端让设密码（code 保留给 /register 复用）
app.post('/login-code', (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase(), code = (req.body.code || '').trim();
  const ip = req.ip || req.connection.remoteAddress || '';
  if (rateLimited('logincode|' + email + '|' + ip, 10, 5 * 60 * 1000)) return res.type('text/plain').send('尝试过于频繁，请稍后再试');
  let u = stmts.getUser.get(email);
  if (!u) {
    // 未注册：仅校验验证码（计数防爆破），成功后保留 code 供 /register
    if (!verifyCode(email, code, false)) return res.type('text/plain').send('验证码错误或已过期');
    return res.json({ register: true });
  }
  if (!verifyCode(email, code, true)) return res.type('text/plain').send('验证码错误或已过期');
  if (u.status === 'banned') return res.type('text/plain').send('该账号已被封禁');
  setCookie(res, createSession(email)); res.redirect('/app');
});
// 注册（验证码登录的新账号 + 设置密码）
app.post('/register', (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase(), code = (req.body.code || '').trim(), password = (req.body.password || '').trim();
  const ip = req.ip || req.connection.remoteAddress || '';
  if (rateLimited('register|' + email + '|' + ip, 10, 5 * 60 * 1000)) return res.type('text/plain').send('尝试过于频繁，请稍后再试');
  if (!verifyCode(email, code, true)) return res.type('text/plain').send('验证码错误或已过期');
  if (password.length < 6) return res.type('text/plain').send('密码至少 6 位');
  stmts.insUser.run(email, Date.now(), email === ADMIN_EMAIL ? 'admin' : 'user');
  stmts.setPassword.run(hashPw(password), email);
  setCookie(res, createSession(email)); res.redirect('/app');
});
// 密码登录（统一错误提示，防账号枚举；限流防爆破）
app.post('/login-password', (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase(), password = (req.body.password || '');
  const ip = req.ip || req.connection.remoteAddress || '';
  if (rateLimited('loginpw|' + email + '|' + ip, 6, 15 * 60 * 1000)) return res.type('text/plain').send('尝试过于频繁，请稍后再试');
  if (!email || !password) return res.type('text/plain').send('邮箱或密码错误');
  const u = stmts.getUser.get(email);
  if (!u || u.status === 'banned' || !u.password_hash || !verifyPw(password, u.password_hash)) {
    return res.type('text/plain').send('邮箱或密码错误');
  }
  setCookie(res, createSession(email)); res.redirect('/app');
});
app.get('/logout', (req, res) => { clearCookie(res); res.redirect('/'); });

// ---------- 拼多多 OAuth/API 回调（独立于本站登录，public） ----------
// PDD 授权/回调会带 code,state 等参数；本站只需接收、记录、返回成功页。
// 与本站邮箱登录完全分开，不混用 session。
app.get('/api/pdd/callback', pddCallback);
app.post('/api/pdd/callback', pddCallback);
function pddCallback(req, res) {
  const ip = req.ip || req.connection.remoteAddress || '';
  if (rateLimited('pdccb|' + ip, 20, 60 * 1000)) return res.status(429).type('text/plain').send('429 请求过于频繁');
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


// 工具选择首页（/app 与 /app/tools 共用）
function appHome(req, res) {
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
  res.type('html').send(layout({ title: '我的工具', userEmail: req.user.email, role: req.user.role, active: 'tools', content: `
    <h1 class="text-2xl font-bold mb-2">我的工具</h1>
    <p class="text-gray-500 mb-6">选择一个工具开始使用</p>
    <div class="grid sm:grid-cols-2 gap-4">${body}</div>` }));
}
app.get('/app', requireUser, appHome);
app.get('/app/tools', requireUser, appHome);
// （所有模块已有专属页面；USER_MODULES 骨架已全部替换）

// ============ P2：比价/监控 ============
const MAX_MONITORS = Number(process.env.MAX_MONITORS || 50);
function today() { const d = new Date(); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); }
// 商品入库 + 记录一次“今日价”（演示源把搜索价当今日真实价）
function ensureProduct(platform, sku, info, price) {
  p2.upsertProduct.run(platform, sku, info.title, info.img || '', info.url || '', price, Date.now(), 'fresh');
  const prod = p2.getProductBySku.get(platform, sku);
  if (info._sign) p2.setExt.run(info._sign, prod.id);
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

// —— 我的链接：API ——
app.get('/api/links', requireUser, (req, res) => {
  const items = p2.listLinks.all(req.user.email).map(r => ({ id: r.id, url: r.url, title: r.title, created_at: r.created_at }));
  res.json({ items });
});
app.post('/api/links', requireUser, (req, res) => {
  const url = (req.body.url || '').trim();
  const title = (req.body.title || '').trim() || url;
  if (url && url.indexOf('http') === 0) {
    p2.addLink.run(req.user.email, url, title, Date.now());
    return res.json({ ok: true });
  }
  res.status(400).json({ ok: false, error: '链接格式不对' });
});
app.delete('/api/links', requireUser, (req, res) => {
  const id = Number(req.body.id);
  if (id) p2.delLink.run(id, req.user.email);
  res.json({ ok: true });
});

// —— 我的链接 页面 ——
app.get('/app/links', requireUser, (req, res) => {
  const s = layout({ title: '我的链接', userEmail: req.user.email, role: req.user.role, active: 'links', content: `
  <div x-data="linksApp()" x-init="init()">
    <h1 class="text-2xl font-bold mb-2">我的链接</h1>
    <p class="text-gray-500 mb-4">保存常用链接。</p>
    <div class="flex gap-2 mb-5">
      <input x-model="title" placeholder="标题(可选)" class="w-40 border rounded-lg px-3 py-2 text-sm">
      <input x-model="url" placeholder="https://..." class="flex-1 border rounded-lg px-3 py-2 text-sm">
      <button @click="add()" class="bg-blue-600 text-white rounded-lg px-4 text-sm">添加</button>
    </div>
    <p x-show="msg" x-text="msg" class="text-sm text-green-600 mb-3"></p>
    <template x-for="l in links" :key="l.id">
      <div class="bg-white border border-gray-100 rounded-xl p-3 mb-2 flex items-center justify-between">
        <div class="min-w-0">
          <div class="font-medium text-sm truncate" x-text="l.title"></div>
          <a :href="l.url" target="_blank" class="text-xs text-blue-500 truncate" x-text="l.url"></a>
        </div>
        <button @click="del(l)" class="text-xs text-red-500">删除</button>
      </div>
    </template>
    <p x-show="links.length===0" class="text-gray-400 text-sm">还没有链接。</p>
  </div>
  <script>
  window.linksApp = function(){ return {
    links:[], url:'', title:'', msg:'',
    init(){ this.load(); },
    async load(){ const r=await fetch('/api/links'); this.links=(await r.json()).items; },
    async add(){ if(!this.url||this.url.indexOf('http')!==0){ this.msg='请填 https:// 开头链接'; return; }
      await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:this.url,title:this.title})});
      this.url=''; this.title=''; this.msg=''; this.load(); },
    async del(l){ await fetch('/api/links',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:l.id})}); this.load(); },
  } };
  </script>` });
  res.type('html').send(s);
});

// ---------- P4：每日报价（非常驻，外部 cron 触发） ----------
const REFRESH_MAX_LOAD = Number(process.env.REFRESH_MAX_LOAD || 2.0);
function getLoad() {
  let l = [0, 0, 0];
  try { l = os.loadavg(); } catch (e) {}
  return { load1: l[0].toFixed(2), load5: l[1].toFixed(2), load15: l[2].toFixed(2), rssMB: Math.round(process.memoryUsage().rss / 1024 / 1024) };
}
// 外部（1Panel 计划任务/定时 curl）调用；按【去重商品】抓一次，供所有监控者共享；负载高则跳过。
app.post('/_/cron/refresh-prices', async (req, res) => {
  // 保护：若设了 CRON_TOKEN，要求请求头 x-cron-token 匹配
  if (process.env.CRON_TOKEN && req.headers['x-cron-token'] !== process.env.CRON_TOKEN) return res.status(401).json({ ok: false, error: 'unauthorized' });
  const l = getLoad();
  if (Number(l.load1) > REFRESH_MAX_LOAD) return res.json({ ok: false, skipped: true, load: l, msg: '负载过高，跳过本次' });
  const products = p2.listDistinctMonitoredProducts.all();
  let refreshed = 0, fail = 0, alerts = 0;
  for (const prod of products) {
    const price = await getCurrentPrice(prod.platform, prod.sku, prod.ext);
    if (price == null) { p2.updatePrice.run(prod.last_price, prod.observed_at, 'stale', prod.id); fail++; continue; }
    const dropped = prod.last_price != null && price < prod.last_price;
    p2.updatePrice.run(price, Date.now(), 'fresh', prod.id);
    p2.insertPricePoint.run(prod.id, today(), price, 'fresh');
    for (const m of p2.listMonitorsByProduct.all(prod.id)) {
      if (m.target_price != null && price <= m.target_price && dropped) { p2.insertAlert.run(m.user_id, prod.id, price, m.target_price, Date.now()); alerts++; }
    }
    refreshed++;
  }
  res.json({ ok: true, load: l, monitoredProducts: products.length, refreshed, fail, alerts });
});

// —— 目标价提醒 ——
app.get('/api/alerts', requireUser, (req, res) => {
  const items = p2.listAlertsByUser.all(req.user.email).map(r => ({ id: r.id, title: r.title, platform: r.platform, url: r.url, price: r.price, target_price: r.target_price, created_at: r.created_at }));
  res.json({ items });
});

// ---------- P5：个人资料 / 设置 ----------
app.get('/api/profile', requireUser, (req, res) => {
  const u = stmts.getUser.get(req.user.email);
  let prof = p2.getProfile.get(req.user.email);
  if (!prof) { p2.upsertProfile.run(req.user.email, '', 1, Date.now()); prof = p2.getProfile.get(req.user.email); }
  res.json({ email: u.email, created: u.created, role: u.role, status: u.status, nickname: prof.nickname || '', alert_enabled: prof.alert_enabled, password_set: !!u.password_hash });
});
app.post('/api/password', requireUser, (req, res) => {
  const u = stmts.getUser.get(req.user.email);
  const current = req.body.current || '';
  const password = (req.body.password || '').trim();
  if (password.length < 6) return res.status(400).json({ ok: false, error: '密码至少 6 位' });
  if (u.password_hash && !verifyPw(current, u.password_hash)) return res.status(400).json({ ok: false, error: '当前密码错误' });
  stmts.setPassword.run(hashPw(password), req.user.email);
  res.json({ ok: true });
});
app.post('/api/profile', requireUser, (req, res) => {
  const nickname = (req.body.nickname || '').slice(0, 50);
  const alert_enabled = (req.body.alert_enabled === 1 || req.body.alert_enabled === '1') ? 1 : 0;
  const prof = p2.getProfile.get(req.user.email);
  p2.upsertProfile.run(req.user.email, nickname, alert_enabled, prof ? prof.created_at : Date.now());
  res.json({ ok: true });
});

app.get('/app/profile', requireUser, (req, res) => {
  const s = layout({ title: '个人资料', userEmail: req.user.email, role: req.user.role, active: 'profile', content: `
  <div x-data="profApp()" x-init="init()">
    <h1 class="text-2xl font-bold mb-2">个人资料</h1>
    <div class="bg-white border border-gray-100 rounded-xl p-6 max-w-xl">
      <div class="grid gap-4">
        <div><div class="text-sm text-gray-500">邮箱</div><div class="font-medium" x-text="email"></div></div>
        <div class="grid grid-cols-2 gap-4">
          <div><div class="text-sm text-gray-500">角色</div><div x-text="role"></div></div>
          <div><div class="text-sm text-gray-500">状态</div><div x-text="status"></div></div>
        </div>
        <div>
          <div class="text-sm text-gray-500 mb-1">昵称</div>
          <input x-model="nickname" placeholder="设置昵称" class="w-full border rounded-lg px-3 py-2 text-sm">
        </div>
        <label class="flex items-center gap-2 text-sm">
          <input type="checkbox" x-model="alert_enabled" :value="alert_enabled" checked="alert_enabled===1"> 开启目标价提醒
        </label>
        <button @click="save()" class="bg-blue-600 text-white rounded-lg px-4 py-2 text-sm w-fit">保存</button>
        <p x-show="msg" x-text="msg" class="text-sm text-green-600"></p>
      </div>
    </div>

    <div class="bg-white border border-gray-100 rounded-xl p-6 max-w-xl mt-6">
      <h2 class="text-lg font-semibold mb-3">设置密码</h2>
      <div class="space-y-3">
        <div x-show="password_set">
          <div class="text-sm text-gray-500 mb-1">当前密码</div>
          <input type="password" x-model="cur" class="w-full border rounded-lg px-3 py-2 text-sm">
        </div>
        <div><div class="text-sm text-gray-500 mb-1">新密码</div><input type="password" x-model="pw1" class="w-full border rounded-lg px-3 py-2 text-sm"></div>
        <div><div class="text-sm text-gray-500 mb-1">确认新密码</div><input type="password" x-model="pw2" class="w-full border rounded-lg px-3 py-2 text-sm"></div>
        <button @click="setPw()" class="bg-blue-600 text-white rounded-lg px-4 py-2 text-sm w-fit">保存密码</button>
        <p x-show="pmsg" x-text="pmsg" class="text-sm" :class="perr?'text-red-600':'text-green-600'"></p>
      </div>
    </div>
  </div>
  <script>
  window.profApp = function(){ return {
    email:'', role:'', status:'', nickname:'', alert_enabled:1, msg:'', password_set:false, cur:'', pw1:'', pw2:'', pmsg:'', perr:false,
    async init(){ const r=await fetch('/api/profile'); const d=await r.json();
      this.email=d.email; this.role=d.role; this.status=d.status; this.nickname=d.nickname; this.alert_enabled=d.alert_enabled; this.password_set=d.password_set; },
    async save(){ await fetch('/api/profile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({nickname:this.nickname,alert_enabled:this.alert_enabled?1:0})}); this.msg='已保存'; },
    async setPw(){ if(this.pw1.length<6){ this.pmsg='密码至少 6 位'; this.perr=true; return; }
      if(this.pw1!==this.pw2){ this.pmsg='两次密码不一致'; this.perr=true; return; }
      const r=await fetch('/api/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current:this.cur,password:this.pw1})});
      const d=await r.json();
      if(d && d.ok){ this.pmsg='密码已更新'; this.perr=false; this.cur=''; this.pw1=''; this.pw2=''; this.password_set=true; }
      else { this.pmsg=(d&&d.error)||'失败'; this.perr=true; } },
  } };
  </script>` });
  res.type('html').send(s);
});

app.get('/app/settings', requireUser, (req, res) => {
  const s = layout({ title: '设置', userEmail: req.user.email, role: req.user.role, active: 'settings', content: `
  <div x-data="setApp()" x-init="init()">
    <h1 class="text-2xl font-bold mb-2">设置</h1>
    <div class="bg-white border border-gray-100 rounded-xl p-6 max-w-xl space-y-5">
      <div class="flex justify-between items-center"><div>每用户监控上限</div><div class="text-sm text-gray-500">${MAX_MONITORS} 个</div></div>
      <label class="flex items-center justify-between text-sm">
        <span>目标价提醒（降幅提醒）</span>
        <input type="checkbox" x-model="alert_enabled" :value="alert_enabled">
      </label>
      <div class="text-sm text-gray-400">提醒当前记录在页面（/app/data 与提醒接口），邮件/钉钉推送敬请期待。</div>
    </div>
  </div>
  <script>
  window.setApp = function(){ return { alert_enabled:1,
    async init(){ const r=await fetch('/api/profile'); this.alert_enabled=(await r.json()).alert_enabled; },
  } };
  </script>` });
  res.type('html').send(s);
});

// ---------- 管理员 ----------
app.get('/admin', requireAdmin, (req, res) => {
  const n = stmts.countUsers.get().n;
  const rows = stmts.listUsers.all().map(r => ({ email: r.email, created: new Date(r.created * 1000).toLocaleString('zh-CN'), role: r.role, status: r.status, super: r.email === ADMIN_EMAIL }));
  const trs = rows.map(u => { const em = escapeHtml(u.email), st = escapeHtml(u.status), role = escapeHtml(u.role), cr = escapeHtml(u.created);
    return `<tr class="border-b border-gray-100">
    <td class="py-2 px-2">${em}</td><td class="py-2 px-2 text-gray-500 text-sm">${cr}</td>
    <td class="py-2 px-2 ${u.role === 'admin' ? 'text-red-600' : 'text-green-600'}">${role}${u.super ? ' ⭐' : ''}</td>
    <td class="py-2 px-2">${st}</td>
    <td class="py-2 px-2 text-xs">${u.super ? '—' : `<button class="btn" data-em="${em}" data-a="role">角色</button> <button class="btn" data-em="${em}" data-a="${u.status === 'banned' ? 'unban' : 'ban'}">${u.status === 'banned' ? '解封' : '封禁'}</button> <button class="btn text-red-500" data-em="${em}" data-a="delete">删除</button>`}</td>
  </tr>`; }).join('');
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
  const l = getLoad();
  const monCount = p2.listDistinctMonitoredProducts.all().length;
  const adminCards = [
    ['负载(1/5/15)', `${l.load1} / ${l.load5} / ${l.load15}`],
    ['进程内存RSS', l.rssMB + ' MB'],
    ['被监控商品(去重)', monCount + ' 个'],
  ].map(c => `<div class="bg-white rounded-xl border border-gray-100 p-5"><div class="text-sm text-gray-500">${c[0]}</div><div class="text-xl font-bold">${c[1]}</div></div>`).join('');
  res.type('html').send(layout({ title: '网站监控', userEmail: req.user.email, role: req.user.role, active: 'admin', content: `
    <h1 class="text-2xl font-bold mb-6">📈 网站监控</h1>
    <div class="grid sm:grid-cols-3 gap-4">${adminCards}</div>
    <div class="bg-white rounded-xl border border-gray-100 p-5 mt-6 text-sm text-gray-600">
      <div class="font-semibold mb-2">每日报价</div>
      <p>由外部定时任务调用 <code class="text-xs bg-gray-100 px-1 rounded">POST /_/cron/refresh-prices</code>。负载高于 1 分钟均值
      <b>${REFRESH_MAX_LOAD}</b> 时自动跳过；按去重商品抓取一次，供所有监控者共享；价格跌破目标价时生成提醒。</p>
      <p class="text-xs text-gray-400 mt-3">当前负载: ${l.load1}（阈值 ${REFRESH_MAX_LOAD}）</p>
    </div>` }) );
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
