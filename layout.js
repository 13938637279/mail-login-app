// layout.js —— 页面骨架（Tailwind CDN + Alpine），统一顶栏/侧边栏
const NAV = [
  { key: 'profile',   icon: '👤', label: '个人资料',   href: '/app/profile' },
  { key: 'monitor',   icon: '🛒', label: '我的商品监控', href: '/app/monitor' },
  { key: 'favorites', icon: '⭐', label: '我的收藏',   href: '/app/favorites' },
  { key: 'links',     icon: '🔗', label: '我的链接',   href: '/app/links' },
  { key: 'data',      icon: '📊', label: '我的数据',   href: '/app/data' },
  { key: 'tools',     icon: '🧰', label: '我的工具',   href: '/app/tools' },
  { key: 'settings',  icon: '⚙️', label: '设置',       href: '/app/settings' },
];

function escape(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function sidebar(active, userEmail, role) {
  const items = NAV.map(n => {
    const on = n.key === active ? 'bg-blue-50 text-blue-600 font-semibold border-l-4 border-blue-500' : 'text-gray-600 hover:bg-gray-100';
    return `<a href="${n.href}" class="flex items-center gap-3 px-4 py-2.5 text-sm rounded-lg ${on}">
      <span class="text-lg">${n.icon}</span><span>${n.label}</span></a>`;
  }).join('');
  // 管理员/超管：多一个「管理后台」入口
  const adminItem = role === 'admin'
    ? `<div class="mt-4 pt-3 border-t border-gray-100">
        <div class="px-4 pb-1 text-[11px] text-gray-400 font-semibold">管理员</div>
        <a href="/admin" class="flex items-center gap-3 px-4 py-2.5 text-sm rounded-lg ${active === 'admin' ? 'bg-amber-50 text-amber-600 font-semibold border-l-4 border-amber-500' : 'text-amber-700 hover:bg-amber-50'}">
          <span class="text-lg">🛠️</span><span>管理后台</span></a>
      </div>` : '';
  return `<aside class="w-60 shrink-0 bg-white border-r border-gray-200 h-full flex flex-col">
    <div class="px-5 py-4 border-b border-gray-100"><div class="text-lg font-bold">wuchenyun</div><div class="text-xs text-gray-400">${escape(userEmail)}</div></div>
    <nav class="p-3 space-y-1 flex-1">${items}${adminItem}</nav>
    <div class="p-3 border-t border-gray-100"><a href="/logout" class="flex items-center gap-2 text-sm text-gray-500 hover:text-red-500">↩ 退出登录</a></div>
  </aside>`;
}

function layout({ title = 'wuchenyun', userEmail = '', role = 'user', active = '', content = '' }) {
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escape(title)}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3/dist/cdn.min.js"></script>
  </head><body class="bg-gray-50 text-gray-900">
  <div class="h-screen flex">
    ${sidebar(active, userEmail, role)}
    <main class="flex-1 overflow-auto p-8">
      <div class="max-w-4xl mx-auto">${content}</div>
    </main>
  </div></body></html>`;
}

module.exports = { layout, NAV };
