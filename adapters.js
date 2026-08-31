// adapters.js —— 取价适配器
// 每个平台一个 adapter，统一提供 async search(keyword)
// 内部可做「官方API优先 → 爬虫兜底」的瀑布取价。
// 目前只有演示数据源(demo)用于跑通 UI/流程；真实平台按同接口接入即可。

const ADAPTERS = {
  demo: {
    name: '演示源',
    async search(kw) {
      const all = [
        { sku: 'D-iphone15',   title: 'Apple iPhone 15 128GB 演示商品', price: 4999, img: '', url: 'https://example.com/d-iphone15' },
        { sku: 'D-iphone15p',  title: 'Apple iPhone 15 Pro 256GB 演示', price: 6999, img: '', url: 'https://example.com/d-iphone15p' },
        { sku: 'D-airpods2',   title: 'AirPods Pro 2 USB-C 演示',       price: 1299, img: '', url: 'https://example.com/d-airpods2' },
        { sku: 'D-huawei60',   title: '华为 Mate 60 512GB 演示',        price: 5999, img: '', url: 'https://example.com/d-huawei60' },
      ];
      const q = (kw || '').trim().toLowerCase();
      return q ? all.filter(p => p.title.toLowerCase().includes(q)) : all;
    },
  },
};

// 遍历所有适配器，汇总 + 去重（platform+sku）
async function searchAll(kw) {
  const results = [];
  for (const key of Object.keys(ADAPTERS)) {
    try {
      const items = (await ADAPTERS[key].search(kw)) || [];
      items.forEach(it => results.push({ platform: key, ...it }));
    } catch (e) { /* 单源失败不影响整体 */ }
  }
  const seen = new Set();
  return results.filter(r => { const k = r.platform + '|' + r.sku; if (seen.has(k)) return false; seen.add(k); return true; });
}

module.exports = { searchAll, ADAPTERS };
