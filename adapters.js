// adapters.js —— 取价适配器（多平台）
// 每平台一个 adapter，统一 async search(keyword)。内部做「官方API优先 → 爬虫兜底」。
// ⚠️ 当前为【演示源】返回样例数据，用于跑通 UI/流程。
//    接真实平台：把对应 adapter 的 search() 换成真实 联盟API/爬虫 调用即可（接口不变）。
//    真实取值需各平台开放平台/联盟 API 密钥；否则只能爬虫（这几家反爬强、有合规/被封风险）。

const PLATFORMS = { jd: '京东', taobao: '淘宝', pdd: '拼多多', douyin: '抖音商城' };

// 样例商品目录（演示用）
const SAMPLE = [
  { title: 'iPhone 15 128GB',    price: 4999 },
  { title: 'iPhone 15 Pro 256GB', price: 6999 },
  { title: 'AirPods Pro 2 USB-C', price: 1299 },
  { title: '华为 Mate 60 512GB',  price: 5999 },
];

function slug(s) { return s.replace(/[^a-zA-Z0-9]+/g, '').slice(0, 10); }

const ADAPTERS = {};
for (const [key, name] of Object.entries(PLATFORMS)) {
  ADAPTERS[key] = {
    name,
    async search(kw) {
      const q = (kw || '').trim().toLowerCase();
      return SAMPLE.filter(p => !q || p.title.toLowerCase().includes(q))
        .map(p => ({
          sku: `${key}-${slug(p.title)}`,
          title: `${p.title}（${name}）`,
          price: Math.round(p.price * (0.9 + Math.random() * 0.2)), // 演示随机价
          img: '',
          url: `https://example.com/${key}/${slug(p.title)}`,
        }));
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

module.exports = { searchAll, ADAPTERS };
