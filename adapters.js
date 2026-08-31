// adapters.js —— 取价适配器（多平台）
// 每平台一个 adapter，统一 async search(keyword)。内部可做「官方API优先 → 爬虫兜底」。
// 当前：pdd 用【官方多多进宝 API】；jd/taobao/douyin 为【演示源】(待接真实源)。
const crypto = require('crypto');

// ---------- PDD 多多进宝（官方 API，签名调用） ----------
// 需环境变量：PDD_CLIENT_ID / PDD_CLIENT_SECRET / PDD_PID
async function pddRequest(api, params) {
  const client_id = process.env.PDD_CLIENT_ID, secret = process.env.PDD_CLIENT_SECRET;
  if (!client_id || !secret) return null;
  const p = { type: api, client_id, timestamp: Date.now(), ...params };
  const keys = Object.keys(p).sort();
  let s = '';
  for (const k of keys) s += k + p[k];
  const sign = crypto.createHash('md5').update(secret + s + secret).digest('hex').toUpperCase();
  p.sign = sign;
  const body = new URLSearchParams(p).toString();
  try {
    const res = await fetch('https://gw-api.pinduoduo.com/api/router', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
    return await res.json();
  } catch (e) { return null; }
}

const ADAPTERS = {
  pdd: {
    name: '拼多多',
    async search(kw) {
      if (!process.env.PDD_CLIENT_ID || !process.env.PDD_PID) return []; // 未配置凭证
      const data = await pddRequest('pdd.ddk.goods.search', { keyword: kw, pid: process.env.PDD_PID, page_size: 20 });
      const list = data && data.goods_search_response ? (data.goods_search_response.goods_list || []) : [];
      return list.map(g => ({
        sku: String(g.goods_id),
        title: g.goods_name,
        price: (Number(g.min_group_price || g.min_normal_price) || 0) / 100, // 分为单位 → 元
        img: g.goods_thumbnail_url || g.goods_image_url || '',
        url: `https://mobile.yangkeduo.com/goods.html?goods_id=${g.goods_id}`,
        _sign: g.goods_sign || '', // 商品签名(详情/报价用)
      }));
    },
    // 按商品签名查当前价（每日报价用）; 入参为 (goodsId, goodsSign)，用 goodsSign 调 detail
    async price(goodsId, goodsSign) {
      if (!process.env.PDD_CLIENT_ID || !process.env.PDD_PID || !goodsSign) return null;
      const data = await pddRequest('pdd.ddk.goods.detail', { goods_sign: goodsSign, pid: process.env.PDD_PID });
      const resp = data && data.goods_detail_response;
      const list = resp ? (resp.goods_details || resp.goods_list || []) : [];
      if (list && list.length) return (Number(list[0].min_group_price) || Number(list[0].min_normal_price) || 0) / 100;
      return null;
    },
  },
};

// ---------- 演示源：jd / taobao / douyin（待接真实源） ----------
const SAMPLE = [
  { title: 'iPhone 15 128GB',    price: 4999 },
  { title: 'iPhone 15 Pro 256GB', price: 6999 },
  { title: 'AirPods Pro 2 USB-C', price: 1299 },
  { title: '华为 Mate 60 512GB',  price: 5999 },
];
const slug = s => s.replace(/[^a-zA-Z0-9]+/g, '').slice(0, 10);
for (const [key, name] of Object.entries({ jd: '京东', taobao: '淘宝', douyin: '抖音商城' })) {
  ADAPTERS[key] = {
    name,
    async search(kw) {
      const q = (kw || '').trim().toLowerCase();
      return SAMPLE.filter(p => !q || p.title.toLowerCase().includes(q))
        .map(p => ({ sku: `${key}-${slug(p.title)}`, title: `${p.title}（${name}）`, price: Math.round(p.price * (0.9 + Math.random() * 0.2)), img: '', url: `https://example.com/${key}/${slug(p.title)}` }));
    },
  };
}

// 遍历所有适配器，汇总 + 去重（platform+sku）；单源失败不影响整体
async function searchAll(kw) {
  const results = [];
  for (const key of Object.keys(ADAPTERS)) {
    try {
      const items = (await ADAPTERS[key].search(kw)) || [];
      items.forEach(it => results.push({ platform: key, ...it }));
    } catch (e) { /* 忽略单源失败 */ }
  }
  const seen = new Set();
  return results.filter(r => { const k = r.platform + '|' + r.sku; if (seen.has(k)) return false; seen.add(k); return true; });
}

// 取一个商品的当前价（返回 null 表示无源/失败）；ext 为平台扩展字段（如 pdd 的 goods_sign）
async function getCurrentPrice(platform, sku, ext) {
  const ad = ADAPTERS[platform];
  if (!ad || typeof ad.price !== 'function') return null;
  try { return await ad.price(sku, ext); } catch (e) { return null; }
}

module.exports = { searchAll, getCurrentPrice, ADAPTERS };
