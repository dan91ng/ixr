<?php
/**
 * IX 中转管理面板 Pro Max + (暗黑毛玻璃美化版 + 极简收纳交互版)
 * 增强：完美比例排版、UUID 大字号自适应、全局分离点击交互(复制与弹窗不冲突)
 */

session_start();

function h($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function normalizeFrontEntryHost($value) {
    $host = trim((string)$value);
    if (strpos($host, '://') !== false) {
        $parsedHost = parse_url($host, PHP_URL_HOST);
        if ($parsedHost) $host = $parsedHost;
    }
    $host = preg_replace('/[\/?#].*$/', '', $host);
    $host = trim($host, " \t\n\r\0\x0B[]");
    if (substr_count($host, ':') === 1 && preg_match('/^(.+):\d+$/', $host, $matches)) {
        $host = $matches[1];
    }
    return $host;
}

function loadFrontEntryHostSetting() {
    $stored = file_exists(FRONT_ENTRY_HOST_FILE) ? trim(file_get_contents(FRONT_ENTRY_HOST_FILE)) : '';
    $env = getenv('IX_PANEL_FRONT_ENTRY_HOST') ?: 'public.example.com';
    return normalizeFrontEntryHost($stored ?: $env ?: 'public.example.com');
}

function currentPublicBaseUrl() {
    $host = $_SERVER['HTTP_X_FORWARDED_HOST'] ?? $_SERVER['HTTP_HOST'] ?? '';
    $host = trim(explode(',', (string)$host)[0]);
    $host = preg_replace('/[^A-Za-z0-9._:-]/', '', $host);
    if ($host === '') return 'https://ix.example.com/';

    $proto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '';
    $proto = strtolower(trim(explode(',', (string)$proto)[0]));
    if ($proto !== 'https' && $proto !== 'http') {
        $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    }
    return $proto . '://' . $host . '/';
}

// ================= 配置区 =================
define('FRONT_ENTRY_HOST_FILE', '/var/lib/' . 'v2' . 'ray-panel/front_entry_host');
define('FRONT_ENTRY_HOST', loadFrontEntryHostSetting());
define('SUB_PUBLIC_BASE_URL', rtrim(getenv('IX_PANEL_PUBLIC_BASE_URL') ?: currentPublicBaseUrl(), '/') . '/');
define('ADMIN_SUB_SECRET_FILE', '/var/lib/' . 'v2' . 'ray-panel/admin_sub_secret');
require_once __DIR__ . '/lib/user_store.php';
require_once __DIR__ . '/lib/ix_admin_xray.php';
// ==========================================

// --- IXR integrated authentication ---
if (isset($_GET['sub'])) {
    outputAdminSubscription();
}
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    session_destroy(); header("Location: /admin.php"); exit;
}
$adminFallbackPassword = (string)(getenv('IXR_ADMIN_PASSWORD') ?: 'change-me');
$adminSessionValid = false;
try {
    $adminSessionValid = ixr_admin_session_valid($adminFallbackPassword);
} catch (Throwable $error) {
    $adminSessionValid = false;
}
if (!$adminSessionValid) {
    $_SESSION = [];
    session_destroy();
    if (isset($_GET['api'])) {
        header('Content-Type: application/json');
        http_response_code(401);
        echo json_encode(['success' => false, 'error' => 'Not logged in']);
        exit;
    }
    header('Location: /admin.php');
    exit;
}
$_SESSION['logged_in'] = true;
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
if (isset($_GET['api'])) {
    ixr_admin_xray_handle_api();
}

function getAdminSubscriptionSecret() {
    if (file_exists(ADMIN_SUB_SECRET_FILE)) return trim(file_get_contents(ADMIN_SUB_SECRET_FILE));
    $secret = bin2hex(random_bytes(32));
    file_put_contents(ADMIN_SUB_SECRET_FILE, $secret);
    @chmod(ADMIN_SUB_SECRET_FILE, 0600);
    return $secret;
}

function currentAdminSubscriptionToken() {
    return substr(hash_hmac('sha256', 'admin-' . date('Ym'), getAdminSubscriptionSecret()), 0, 32);
}

function buildVmessLink($node, $inboundPort) {
    if (empty($node['frontend_uuid'])) return '';
    $config = [
        'v' => '2',
        'ps' => 'HKIX|' . ($node['tag'] ?? '') . '-' . ($node['config_ip'] ?? ''),
        'add' => FRONT_ENTRY_HOST,
        'port' => (string)$inboundPort,
        'id' => $node['frontend_uuid'],
        'aid' => '0',
        'scy' => 'auto',
        'net' => 'tcp',
        'type' => 'none',
        'host' => '',
        'path' => '',
        'tls' => '',
        'sni' => '',
        'alpn' => '',
        'fp' => '',
        'insecure' => '0'
    ];
    return 'vmess://' . base64_encode(json_encode($config, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
}

function buildSurgeProxyLine($node, $inboundPort) {
    if (empty($node['frontend_uuid'])) return '';
    $name = 'HKIX|' . ($node['tag'] ?? '') . '-' . ($node['config_ip'] ?? '');
    $name = preg_replace('/[\r\n,=]+/', '-', $name);
    return sprintf(
        '%s = vmess, %s, %d, username=%s, vmess-aead=true',
        $name,
        FRONT_ENTRY_HOST,
        (int)$inboundPort,
        $node['frontend_uuid']
    );
}

function outputAdminSubscription() {
    $token = $_GET['sub'] ?? '';
    if (!hash_equals(currentAdminSubscriptionToken(), $token)) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo 'invalid token';
        exit;
    }
    $format = strtolower(trim($_GET['format'] ?? 'v2ray'));
    if (!in_array($format, ['v2ray', 'surge'], true)) {
        http_response_code(400);
        header('Content-Type: text/plain; charset=utf-8');
        echo 'unsupported subscription format';
        exit;
    }
    if ($format === 'surge') {
        $data = buildPanelData();
        $lines = [];
        foreach ($data['nodes'] as $node) {
            $line = buildSurgeProxyLine($node, $data['inbound_port']);
            if ($line) $lines[] = $line;
        }
        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: inline; filename=hkix-surge.conf');
        echo implode(chr(10), $lines);
        exit;
    }
    $data = buildPanelData();
    $links = [];
    foreach ($data['nodes'] as $node) {
        $link = buildVmessLink($node, $data['inbound_port']);
        if ($link) $links[] = $link;
    }
    header('Content-Type: text/plain; charset=utf-8');
    echo base64_encode(implode("\n", $links));
    exit;
}

function buildPanelData(): array
{
    return ixr_admin_xray_panel_data();
}


?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8"><title>统一出口管理 | 线路管理</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: #f8fafc; }
        .glass-nav { background: rgba(30, 41, 59, 0.85); backdrop-filter: blur(12px); border-bottom: 1px solid rgba(255,255,255,0.1); }
        .click-to-edit { border-bottom: 2px dashed #cbd5e1; transition: all 0.2s ease; display: inline-block; padding-bottom: 1px; }
        .click-to-edit:hover { border-bottom-color: #6366f1; color: #4f46e5; }
        .table-header { background: rgba(248, 250, 252, 0.9); backdrop-filter: blur(4px); }
        .custom-scrollbar::-webkit-scrollbar { width: 6px; height: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #94a3b8; }
        .modal-enter { opacity: 1; transform: scale(1); }
        :root { --ixr-bg:#f4f7fb; --ixr-card:#fff; --ixr-text:#172033; --ixr-muted:#64748b; --ixr-line:#e5eaf3; --ixr-blue:#2563eb; --ixr-purple:#7c3aed; --ixr-green:#16a34a; --ixr-red:#ef4444; --ixr-amber:#f59e0b; --ixr-shadow:0 12px 30px #1f293714; }
        body.ix-admin-integrated { background:var(--ixr-bg) !important; color:var(--ixr-text); padding:0 0 24px !important; }
        body.ix-admin-integrated[data-embedded="1"] { background:transparent !important; }
        body.ix-admin-integrated .glass-nav { position:static !important; margin:0 0 16px; padding:22px 24px !important; background:linear-gradient(135deg,var(--ixr-blue),var(--ixr-purple)) !important; border:0 !important; border-radius:22px; box-shadow:0 16px 36px #1f293722; color:#fff; }
        body.ix-admin-integrated[data-embedded="1"] .glass-nav { background:var(--ixr-card) !important; color:var(--ixr-text); border:1px solid #edf1f7 !important; box-shadow:var(--ixr-shadow); }
        body.ix-admin-integrated .ix-hero-inner { display:flex; align-items:center; justify-content:space-between; gap:18px; max-width:none; margin:0; }
        body.ix-admin-integrated .ix-kicker { display:inline-flex; align-items:center; gap:8px; color:#dbeafe; font-size:12px; font-weight:900; letter-spacing:.08em; text-transform:uppercase; }
        body.ix-admin-integrated[data-embedded="1"] .ix-kicker { color:var(--ixr-blue); }
        body.ix-admin-integrated .ix-hero-title { margin:4px 0 6px; display:flex; align-items:center; gap:10px; font-size:25px; line-height:1.15; font-weight:950; color:inherit; }
        body.ix-admin-integrated .ix-hero-title i { color:#bfdbfe; }
        body.ix-admin-integrated[data-embedded="1"] .ix-hero-title i { color:var(--ixr-blue); }
        body.ix-admin-integrated .ix-hero-subtitle { margin:0; color:#e0e7ff; font-size:14px; }
        body.ix-admin-integrated[data-embedded="1"] .ix-hero-subtitle { color:var(--ixr-muted); }
        body.ix-admin-integrated .ix-port-row { margin-top:12px; display:flex; flex-wrap:wrap; gap:8px; }
        body.ix-admin-integrated .ix-port-pill { display:inline-flex; align-items:center; gap:9px; border:1px solid rgba(255,255,255,.22); background:rgba(15,23,42,.24); color:#fff; border-radius:999px; padding:8px 12px; font-size:13px; font-weight:900; }
        body.ix-admin-integrated[data-embedded="1"] .ix-port-pill { border-color:#dbe3ef; background:#f8fafc; color:#334155; }
        body.ix-admin-integrated .ix-port-pill b { font-family:Consolas,monospace; color:inherit; }
        body.ix-admin-integrated .ix-toolbar { display:flex; gap:9px; flex-wrap:wrap; justify-content:flex-end; }
        body.ix-admin-integrated .ix-action { display:inline-flex; align-items:center; gap:8px; border:0 !important; border-radius:11px !important; padding:10px 13px !important; background:#eef2ff !important; color:#3730a3 !important; text-decoration:none; font-size:13px; font-weight:900 !important; box-shadow:none !important; transition:.18s ease; cursor:pointer; }
        body.ix-admin-integrated .ix-action:hover { background:#e0e7ff !important; transform:translateY(-1px); filter:none !important; }
        body.ix-admin-integrated .ix-action.primary { background:linear-gradient(135deg,var(--ixr-blue),var(--ixr-purple)) !important; color:#fff !important; box-shadow:0 8px 18px #2563eb28 !important; }
        body.ix-admin-integrated .ix-action.danger { background:#fff1f2 !important; color:#be123c !important; }
        body.ix-admin-integrated .ix-admin-summary { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; margin:0 0 16px; }
        body.ix-admin-integrated .ix-admin-metric { display:flex; align-items:center; gap:13px; background:#fff; border:1px solid var(--ixr-line); border-radius:18px; padding:15px 16px; box-shadow:var(--ixr-shadow); }
        body.ix-admin-integrated .ix-admin-metric i { width:38px; height:38px; border-radius:13px; display:grid; place-items:center; color:#fff; background:linear-gradient(135deg,var(--ixr-blue),var(--ixr-purple)); box-shadow:0 8px 18px #2563eb25; }
        body.ix-admin-integrated .ix-admin-metric span { display:block; color:var(--ixr-muted); font-size:12px; font-weight:800; }
        body.ix-admin-integrated .ix-admin-metric b { display:block; margin-top:4px; color:var(--ixr-text); font-size:24px; line-height:1; }
        body.ix-admin-integrated #ixFrontHostMetric { font-size:17px; line-height:1.25; word-break:break-all; }
        body.ix-admin-integrated .ix-admin-layout { max-width:none !important; margin:0 !important; padding:0 !important; gap:16px !important; align-items:start; }
        body.ix-admin-integrated .ix-card, body.ix-admin-integrated .ix-card-like { background:var(--ixr-card) !important; border:1px solid #edf1f7 !important; border-radius:18px !important; box-shadow:var(--ixr-shadow) !important; overflow:hidden; }
        body.ix-admin-integrated .ix-card > div:first-child, body.ix-admin-integrated .ix-card-like > div:first-child { background:#fbfdff !important; border-color:var(--ixr-line) !important; }
        body.ix-admin-integrated input, body.ix-admin-integrated select { border:1px solid #d8deea !important; border-radius:12px !important; background:#fff !important; }
        body.ix-admin-integrated input:focus, body.ix-admin-integrated select:focus { box-shadow:0 0 0 3px #2563eb22 !important; border-color:var(--ixr-blue) !important; }
        body.ix-admin-integrated button { border-radius:11px !important; font-weight:900 !important; transition:.18s ease; }
        body.ix-admin-integrated button:hover { filter:brightness(.97); }
        body.ix-admin-integrated button.bg-slate-800, body.ix-admin-integrated button.bg-indigo-600, body.ix-admin-integrated button.bg-purple-600 { background:linear-gradient(135deg,var(--ixr-blue),var(--ixr-purple)) !important; color:#fff !important; box-shadow:0 8px 18px #2563eb28 !important; }
        body.ix-admin-integrated table { min-width:760px; border-collapse:collapse !important; }
        body.ix-admin-integrated thead, body.ix-admin-integrated .table-header { background:#f8fafc !important; backdrop-filter:none !important; }
        body.ix-admin-integrated th { color:#475569 !important; text-transform:none !important; letter-spacing:0 !important; font-size:13px !important; }
        body.ix-admin-integrated th, body.ix-admin-integrated td { border-color:var(--ixr-line) !important; padding:12px 14px !important; }
        body.ix-admin-integrated tbody tr:hover { background:#eef2ff66 !important; }
        body.ix-admin-integrated .modal-enter { opacity:1; transform:scale(1); }
        body.ix-admin-integrated #nodeModalCard, body.ix-admin-integrated #clientModalCard, body.ix-admin-integrated #passwordModalCard, body.ix-admin-integrated #subscriptionModalCard { border:1px solid #edf1f7; border-radius:18px !important; box-shadow:0 24px 70px #11182730 !important; }
        body.ix-admin-integrated .node-type-badge { display:inline-flex; align-items:center; gap:5px; border-radius:999px; padding:3px 8px; font-size:11px; font-weight:900; }
        body.ix-admin-integrated .node-type-badge.ix { background:#ede9fe; color:#6d28d9; border:1px solid #ddd6fe; }
        body.ix-admin-integrated .node-type-badge.ixr { background:#dbeafe; color:#1d4ed8; border:1px solid #bfdbfe; }
        @media (max-width: 900px) { body.ix-admin-integrated .ix-hero-inner { flex-direction:column; align-items:flex-start; } body.ix-admin-integrated .ix-toolbar { justify-content:flex-start; } body.ix-admin-integrated .ix-action-label { display:none; } }
    </style>
</head>
<body class="text-slate-800 antialiased selection:bg-indigo-100 selection:text-indigo-900 pb-16 relative ix-admin-integrated" data-embedded="<?=isset($_GET['embedded']) ? '1' : '0'?>">

    <nav class="glass-nav">
        <div class="ix-hero-inner">
            <div>
                <h1 class="ix-hero-title"><i class="fa-solid fa-diagram-project"></i>统一出口管理</h1>
                <div class="ix-port-row">
                    <button type="button" id="inboundPortBtn" onclick="editInboundPort()" class="ix-port-pill" title="点击修改主监听端口">
                        <i class="fa-solid fa-satellite-dish"></i><span>监听端口</span><b id="inboundPort">---</b>
                    </button>
                    <button type="button" id="frontEntryHostBtn" onclick="editFrontEntryHost()" class="ix-port-pill" title="点击修改导出 VMess 的连接地址">
                        <i class="fa-solid fa-globe"></i><span>连接地址</span><b id="frontEntryHost">---</b>
                    </button>
                </div>
            </div>
            <div class="ix-toolbar">
                <a href="/admin.php?section=ix-admin" class="ix-action" title="返回线路管理"><i class="fa-solid fa-house"></i><span class="ix-action-label">线路管理</span></a>
                <button id="testIpBtn" onclick="testNodeIps()" class="ix-action" title="穿透测速"><i class="fa-solid fa-network-wired"></i><span class="ix-action-label">穿透测速</span></button>
                <button id="rebootBtn" onclick="restartService()" class="ix-action primary" title="重新应用 Xray"><i class="fa-solid fa-rotate"></i><span class="ix-action-label">应用 Xray</span></button>
                <button onclick="copySubscriptionUrl()" class="ix-action" title="复制订阅"><i class="fa-solid fa-rss"></i><span class="ix-action-label">订阅</span></button>
                <a href="<?=h(getenv('IX_PANEL_GRAFANA_URL') ?: '#')?>" target="_blank" rel="noopener noreferrer" class="ix-action" title="Grafana 监控"><i class="fa-solid fa-chart-line"></i><span class="ix-action-label">监控</span></a>
                <?php if (!isset($_GET['embedded'])): ?>
                    <a href="/admin.php?section=account" class="ix-action" title="修改密码"><i class="fa-solid fa-key"></i><span class="ix-action-label">修改密码</span></a>
                    <a href="?action=logout" class="ix-action danger" title="退出登录"><i class="fa-solid fa-power-off"></i><span class="ix-action-label">退出登录</span></a>
                <?php endif; ?>
            </div>
        </div>
    </nav>

    <div class="ix-admin-summary">
        <div class="ix-admin-metric"><i class="fa-solid fa-server"></i><div><span>全部出口</span><b id="ixNodeCount">--</b></div></div>
        <div class="ix-admin-metric"><i class="fa-solid fa-route"></i><div><span>IX 线路</span><b id="ixRouteCount">--</b></div></div>
        <div class="ix-admin-metric"><i class="fa-solid fa-shuffle"></i><div><span>IXR 专用</span><b id="ixrOnlyCount">--</b></div></div>
        <div class="ix-admin-metric"><i class="fa-solid fa-users"></i><div><span>前端用户</span><b id="ixClientCount">--</b></div></div>
        <div class="ix-admin-metric"><i class="fa-solid fa-satellite-dish"></i><div><span>监听端口</span><b id="ixInboundMetric">--</b></div></div>
    </div>

    <!-- 主容器 -->
    <div class="ix-admin-layout max-w-[1500px] mx-auto mt-8 px-4 grid grid-cols-1 xl:grid-cols-12 gap-8">

        <!-- 左侧：节点与路由区 (比例 7) -->
        <div class="xl:col-span-7 space-y-6">

            <div class="ix-card bg-white p-6 rounded-2xl min-h-[154px] flex flex-col justify-between shadow-sm border border-slate-200 hover:shadow-md transition-shadow">
                <div class="flex items-center justify-between gap-3 mb-5">
                    <h3 class="font-bold text-slate-800 text-lg flex items-center"><i class="fa-solid fa-link mr-2 text-indigo-500 bg-indigo-50 p-2 rounded-lg"></i>新增出口节点</h3>
                    <button type="button" onclick="openCreateNodeModal()" class="text-sm font-bold text-indigo-600 bg-indigo-50 hover:bg-indigo-100 border border-indigo-100 px-4 py-2 rounded-xl transition"><i class="fa-solid fa-sliders mr-2"></i>手动新增</button>
                </div>
                <div class="flex gap-3 relative">
                    <div class="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none"><i class="fa-solid fa-paste text-slate-400"></i></div>
                    <input type="text" id="vmessInput" placeholder="在此粘贴 vmess:// 链接..." class="flex-1 bg-slate-50 border border-slate-200 rounded-xl pl-11 pr-4 py-3 focus:bg-white focus:ring-2 focus:ring-indigo-500 outline-none transition-all text-sm shadow-inner">
                    <button id="addNodeBtn" type="button" onclick="addNode(event)" class="bg-slate-800 text-white px-8 py-3 rounded-xl hover:bg-slate-700 transition shadow-md font-medium whitespace-nowrap flex items-center">
                        <i class="fa-solid fa-plus mr-2"></i>添加
                    </button>
                </div>
                <label class="mt-4 flex items-center gap-3 text-sm font-bold text-slate-700 cursor-pointer w-fit">
                    <input type="checkbox" id="importEnableIx" checked class="w-4 h-4 accent-indigo-600">
                    <span>同时加入 IX 线路并生成前端连接</span>
                </label>
                <div class="flex flex-wrap items-end gap-3">
                    <label class="flex-1 min-w-[140px] text-sm font-bold text-slate-700">监听端口
                        <input type="number" id="sharedInboundPortInput" min="1" max="65535" step="1" placeholder="1–65535" class="mt-2 w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-sm">
                    </label>
                    <button type="button" id="saveSharedInboundPortBtn" onclick="saveSharedInboundPort()" class="bg-indigo-600 text-white px-6 py-3 rounded-xl font-bold">保存端口</button>
                    <p class="w-full text-xs text-slate-500">修改实际 Xray 共享监听端口并同步线路导出端口；不影响 Web 端口。请同步调整防火墙及前置转发。</p>
                </div>
                </div>
            </div>

            <div class="ix-card bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden hover:shadow-md transition-shadow flex flex-col">
                <div class="p-5 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
                    <h3 class="font-bold text-slate-800 text-lg flex items-center"><i class="fa-solid fa-server mr-2 text-blue-500 bg-blue-50 p-2 rounded-lg"></i>全部出口节点</h3>
                    <span class="text-xs font-medium text-slate-500 bg-white border px-3 py-1 rounded-full shadow-sm">点击名称编辑完整配置 | IX 线路可绑定前端用户</span>
                </div>
                <div class="overflow-x-auto custom-scrollbar">
                    <table class="w-full text-left border-collapse">
                        <thead class="table-header text-slate-500 text-xs font-bold uppercase tracking-wider sticky top-0 z-10">
                            <tr>
                                <th class="px-5 py-4 border-b border-slate-200">出口名称 / 类型 / UUID</th>
                                <th class="px-5 py-4 border-b border-slate-200">落地地址 / 探测出口</th>
                                <th class="px-5 py-4 border-b border-slate-200 min-w-[220px]">IX 线路设置</th>
                                <th class="px-5 py-4 border-b border-slate-200 text-center">操作</th>
                            </tr>
                        </thead>
                        <tbody id="nodeTable" class="divide-y divide-slate-100 text-sm"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- 右侧：入站用户区 (比例 5) -->
        <div class="xl:col-span-5 flex flex-col gap-6">
            <div class="ix-card bg-white p-6 rounded-2xl min-h-[154px] flex flex-col justify-between shadow-sm border border-slate-200 hover:shadow-md transition-shadow">
                <div class="flex items-center justify-between mb-5">
                    <h3 class="font-bold text-slate-800 text-lg flex items-center"><i class="fa-solid fa-globe mr-2 text-emerald-500 bg-emerald-50 p-2 rounded-lg"></i>导出连接地址</h3>
                </div>
                <div style="display:grid;grid-template-columns:minmax(0,1fr) minmax(140px,180px);gap:16px;align-items:start">
                <div class="grid grid-cols-1 gap-3">
                    <input type="text" id="frontEntryHostInput" placeholder="填写前置转发域名或 IP" class="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 focus:bg-white focus:ring-2 focus:ring-indigo-500 outline-none transition-all text-sm shadow-inner">
                    <button onclick="saveFrontEntryHostFromInput()" class="self-end bg-indigo-600 text-white px-6 py-3 rounded-xl hover:bg-indigo-700 transition shadow-md font-bold whitespace-nowrap flex items-center justify-center">
                        <i class="fa-solid fa-floppy-disk mr-2"></i>保存地址
                    </button>
                </div>
            </div>

            <div class="ix-card bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden hover:shadow-md transition-shadow flex flex-col h-full">
                <div class="p-5 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
                    <h3 class="font-bold text-slate-800 text-lg flex items-center"><i class="fa-solid fa-users mr-2 text-purple-500 bg-purple-50 p-2 rounded-lg"></i>前端用户配置</h3>
                    <span class="text-xs font-medium text-slate-500 bg-white border px-3 py-1 rounded-full shadow-sm">点击整行编辑前端连接UUID | 点击UUID复制</span>
                </div>
                <div class="overflow-x-auto custom-scrollbar flex-1">
                    <table class="w-full text-left border-collapse">
                        <thead class="table-header text-slate-500 text-xs font-bold uppercase tracking-wider sticky top-0 z-10">
                            <tr>
                                <th class="px-5 py-4 border-b border-slate-200">前端用户标识 (Email)</th>
                                <th class="px-5 py-4 border-b border-slate-200">前端连接UUID</th>
                            </tr>
                        </thead>
                        <tbody id="clientTable" class="divide-y divide-slate-100"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <div id="nodeModal" class="fixed inset-0 bg-slate-900/60 backdrop-blur-sm hidden items-start justify-center z-50 transition-opacity opacity-0 overflow-y-auto px-4 py-6">
        <div id="nodeModalCard" class="bg-white rounded-3xl shadow-2xl w-full max-w-5xl p-7 transform scale-95 transition-all duration-300 my-auto">
            <div class="flex justify-between items-start gap-5 mb-6">
                <div>
                    <div class="flex items-center gap-3"><h3 id="modalModeTitle" class="text-xl font-bold text-slate-800">编辑出口节点</h3><span id="modalNodeType" class="node-type-badge ixr">IXR 专用</span></div>
                    <p class="text-sm text-slate-500 mt-2">统一维护出口地址、探测端口、VMess 传输参数和 IX 线路属性。</p>
                </div>
                <button type="button" onclick="closeNodeModal()" class="text-slate-400 hover:text-slate-600 p-2"><i class="fa-solid fa-xmark text-xl"></i></button>
            </div>
            <input type="hidden" id="modalOldTag">
            <div class="space-y-6">
                <section class="bg-slate-50/80 border border-slate-200 rounded-2xl p-5">
                    <h4 class="font-bold text-slate-800 mb-4 flex items-center"><i class="fa-solid fa-server text-indigo-500 mr-2"></i>基础配置</h4>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-3">
                        <div><label class="block text-xs font-bold text-slate-500 mb-1.5">出口名称</label><input type="text" id="modalTag" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm font-bold text-slate-800 focus:ring-2 focus:ring-indigo-500 outline-none"></div>
                        <div><label class="block text-xs font-bold text-slate-500 mb-1.5">本地探测端口</label><input type="number" id="modalProbePort" placeholder="新增时留空自动分配" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm font-mono text-slate-700 focus:ring-2 focus:ring-indigo-500 outline-none"></div>
                        <div><label class="block text-xs font-bold text-slate-500 mb-1.5">服务器地址</label><input type="text" id="modalAddress" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm font-mono text-slate-700 focus:ring-2 focus:ring-indigo-500 outline-none"></div>
                        <div><label class="block text-xs font-bold text-slate-500 mb-1.5">远端端口</label><input type="number" id="modalPort" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm font-mono text-slate-700 focus:ring-2 focus:ring-indigo-500 outline-none"></div>
                        <div class="md:col-span-2"><label class="block text-xs font-bold text-slate-500 mb-1.5">用户 ID / UUID</label><input type="text" id="modalUuid" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-[13px] font-mono text-slate-700 focus:ring-2 focus:ring-indigo-500 outline-none"></div>
                    </div>
                </section>
                <section class="bg-slate-50/80 border border-slate-200 rounded-2xl p-5">
                    <h4 class="font-bold text-slate-800 mb-4 flex items-center"><i class="fa-solid fa-sliders text-blue-500 mr-2"></i>VMess 与传输配置</h4>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-x-4 gap-y-3">
                        <div><label class="block text-xs font-bold text-slate-500 mb-1.5">AlterID</label><input type="number" id="modalAid" value="0" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500 outline-none"></div>
                        <div><label class="block text-xs font-bold text-slate-500 mb-1.5">Security</label><input type="text" id="modalSecurity" value="auto" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500 outline-none"></div>
                        <div><label class="block text-xs font-bold text-slate-500 mb-1.5">Network</label><select id="modalNetwork" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500 outline-none"><option value="tcp">tcp</option><option value="ws">ws</option><option value="grpc">grpc</option></select></div>
                        <div><label class="block text-xs font-bold text-slate-500 mb-1.5">伪装 Type</label><input type="text" id="modalHeaderType" value="none" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500 outline-none"></div>
                        <div><label class="block text-xs font-bold text-slate-500 mb-1.5">TLS</label><select id="modalTls" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500 outline-none"><option value="">关闭</option><option value="tls">tls</option></select></div>
                        <div><label class="block text-xs font-bold text-slate-500 mb-1.5">允许不安全</label><select id="modalInsecure" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500 outline-none"><option value="0">否</option><option value="1">是</option></select></div>
                        <div><label class="block text-xs font-bold text-slate-500 mb-1.5">Host</label><input type="text" id="modalHost" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500 outline-none"></div>
                        <div><label class="block text-xs font-bold text-slate-500 mb-1.5">Path / ServiceName</label><input type="text" id="modalPath" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500 outline-none"></div>
                        <div><label class="block text-xs font-bold text-slate-500 mb-1.5">SNI</label><input type="text" id="modalSni" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500 outline-none"></div>
                        <div><label class="block text-xs font-bold text-slate-500 mb-1.5">ALPN</label><input type="text" id="modalAlpn" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500 outline-none"></div>
                        <div><label class="block text-xs font-bold text-slate-500 mb-1.5">Fingerprint</label><input type="text" id="modalFp" class="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500 outline-none"></div>
                    </div>
                </section>
                <section class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <label class="flex items-center justify-between bg-indigo-50 border border-indigo-100 rounded-2xl px-5 py-4 cursor-pointer hover:bg-indigo-100/70 transition"><span><b class="block text-slate-800">启用 IX 线路</b><small class="text-slate-500">生成共享入口线路，可供用户授权及前端连接使用</small></span><input type="checkbox" id="modalEnableIx" onchange="syncNodeTypeControls()" class="w-5 h-5 accent-indigo-600"></label>
                    <label id="modalShowOnFrontWrap" class="flex items-center justify-between bg-purple-50 border border-purple-100 rounded-2xl px-5 py-4 cursor-pointer hover:bg-purple-100/70 transition"><span><b class="block text-slate-800">前台显示</b><small class="text-slate-500">控制管理员 IX 订阅是否显示该线路</small></span><input type="checkbox" id="modalShowOnFront" class="w-5 h-5 accent-purple-600"></label>
                </section>
            </div>
            <div class="mt-7 flex justify-end gap-3">
                <button type="button" onclick="closeNodeModal()" class="px-5 py-3 rounded-xl font-bold text-slate-600 bg-slate-100 hover:bg-slate-200 transition">取消</button>
                <button id="modalSaveButton" type="button" onclick="saveNodeModal()" class="px-7 py-3 rounded-xl bg-indigo-600 text-white font-bold hover:bg-indigo-700 transition shadow-lg shadow-indigo-500/30">保存并应用</button>
            </div>
        </div>
    </div>

    <!-- 弹窗：编辑前端用户 UUID -->
    <div id="clientModal" class="fixed inset-0 bg-slate-900/60 backdrop-blur-sm hidden items-center justify-center z-50 transition-opacity opacity-0">
        <div id="clientModalCard" class="bg-white rounded-3xl shadow-2xl w-[420px] p-7 transform scale-95 transition-all duration-300">
            <div class="flex justify-between items-center mb-6">
                <h3 class="text-xl font-bold text-slate-800">配置前端用户</h3>
                <button onclick="closeClientModal()" class="text-slate-400 hover:text-slate-600"><i class="fa-solid fa-xmark text-xl"></i></button>
            </div>
            <div class="mb-4 text-center">
                <span class="inline-block bg-purple-50 text-purple-700 border border-purple-100 font-bold px-4 py-1.5 rounded-full text-sm" id="modalClientEmailDisplay"></span>
            </div>
            <input type="hidden" id="modalClientEmail">
            <div class="space-y-4">
                <div>
                    <label class="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1.5 text-center">前端连接 UUID (清空则重新生成)</label>
                    <input type="text" id="modalClientUuid" class="w-full text-center bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-[13px] font-mono text-slate-600 focus:bg-white focus:ring-2 focus:ring-purple-500 outline-none transition">
                </div>
            </div>
            <div class="mt-8">
                <button onclick="saveClientModal()" class="w-full bg-purple-600 text-white font-bold py-3.5 rounded-xl hover:bg-purple-700 transition shadow-lg shadow-purple-500/30">确认保存</button>
            </div>
        </div>
    </div>

    <!-- 弹窗：修改后台密码 -->
    <div id="passwordModal" class="fixed inset-0 bg-slate-900/60 backdrop-blur-sm hidden items-center justify-center z-50 transition-opacity opacity-0">
        <div id="passwordModalCard" class="bg-white rounded-3xl shadow-2xl w-[420px] p-7 transform scale-95 transition-all duration-300">
            <div class="flex justify-between items-center mb-6">
                <h3 class="text-xl font-bold text-slate-800">修改后台密码</h3>
                <button onclick="closePasswordModal()" class="text-slate-400 hover:text-slate-600"><i class="fa-solid fa-xmark text-xl"></i></button>
            </div>
            <div class="space-y-4">
                <input type="password" id="currentPass" placeholder="当前密码" class="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-sm text-slate-800 focus:bg-white focus:ring-2 focus:ring-indigo-500 outline-none transition">
                <input type="password" id="newPass" placeholder="新密码，至少 6 位" class="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-sm text-slate-800 focus:bg-white focus:ring-2 focus:ring-indigo-500 outline-none transition">
                <input type="password" id="confirmPass" placeholder="确认新密码" class="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-sm text-slate-800 focus:bg-white focus:ring-2 focus:ring-indigo-500 outline-none transition">
            </div>
            <div class="mt-8">
                <button onclick="savePasswordModal()" class="w-full bg-slate-800 text-white font-bold py-3.5 rounded-xl hover:bg-slate-700 transition shadow-lg shadow-slate-500/20">确认修改</button>
            </div>
        </div>
    </div>

    <div id="toast" class="fixed bottom-6 right-6 transform translate-y-24 opacity-0 transition-all duration-300 ease-out px-6 py-4 rounded-xl shadow-2xl z-50 flex items-center gap-3 text-white font-medium max-w-md pointer-events-none border border-white/10 backdrop-blur-md"></div>

    <div id='subscriptionModal' onclick='if(event.target===this) closeSubscriptionModal()' class='fixed inset-0 bg-slate-900/60 backdrop-blur-sm hidden items-center justify-center z-[60] transition-opacity opacity-0 px-4'>
        <div id='subscriptionModalCard' class='bg-white rounded-3xl shadow-2xl w-full max-w-[460px] p-7 transform scale-95 transition-all duration-300'>
            <div class='flex justify-between items-start gap-4 mb-6'>
                <div class='flex items-center gap-3'>
                    <div class='w-11 h-11 rounded-2xl bg-indigo-50 text-indigo-600 flex items-center justify-center'><i class='fa-solid fa-rss text-lg'></i></div>
                    <div><h3 class='text-xl font-bold text-slate-800'>选择订阅格式</h3></div>
                </div>
                <button onclick='closeSubscriptionModal()' class='text-slate-400 hover:text-slate-600 p-1'><i class='fa-solid fa-xmark text-xl'></i></button>
            </div>
            <div class='space-y-3'>
                <button onclick='copyVmessSubscription()' class='w-full text-left border border-slate-200 hover:border-indigo-300 hover:bg-indigo-50/60 rounded-2xl p-4 transition-all group flex items-center gap-4'>
                    <span class='w-11 h-11 rounded-xl bg-indigo-100 text-indigo-600 flex items-center justify-center group-hover:bg-indigo-600 group-hover:text-white transition-colors'><i class='fa-solid fa-link'></i></span>
                    <span class='flex-1'><span class='block font-bold text-slate-800'>VMess 订阅链接</span><span class='block text-xs text-slate-500 mt-1'>适用于 v2rayN、v2rayNG、Shadowrocket 等客户端</span></span>
                    <i class='fa-solid fa-chevron-right text-slate-300 group-hover:text-indigo-500'></i>
                </button>
                <button onclick='copySurgeSubscription()' class='w-full text-left border border-slate-200 hover:border-purple-300 hover:bg-purple-50/60 rounded-2xl p-4 transition-all group flex items-center gap-4'>
                    <span class='w-11 h-11 rounded-xl bg-purple-100 text-purple-600 flex items-center justify-center group-hover:bg-purple-600 group-hover:text-white transition-colors'><i class='fa-solid fa-wave-square'></i></span>
                    <span class='flex-1'><span class='block font-bold text-slate-800'>Surge 订阅链接</span><span class='block text-xs text-slate-500 mt-1'>Surge 外部策略列表格式，可用于 policy-path</span></span>
                    <i class='fa-solid fa-chevron-right text-slate-300 group-hover:text-purple-500'></i>
                </button>
            </div>
        </div>
    </div>

    <script>
        let clientsCache = [];
        let nodesCache = [];
        let currentInboundPort = '';
        let frontEntryHost = <?= json_encode(FRONT_ENTRY_HOST) ?>;
        let addNodePending = false;
        const SUB_URL = <?= json_encode(SUB_PUBLIC_BASE_URL . 'ix-admin.php?sub=' . currentAdminSubscriptionToken(), JSON_UNESCAPED_SLASHES) ?>;
        const SURGE_SUB_URL = SUB_URL + '&format=surge';

        // 剪贴板复制，使用 stopPropagation 阻止冒泡触发弹窗
        function copyText(event, text) {
            event.stopPropagation();
            navigator.clipboard.writeText(text).then(() => {
                showToast('UUID 已成功复制到剪贴板', 'success');
            }).catch(err => {
                showToast('复制失败，请手动选择复制', 'error');
            });
        }

        function encodeBase64Utf8(text) {
            return btoa(unescape(encodeURIComponent(text)));
        }

        function escapeHtml(value) {
            return String(value ?? '').replace(/[&<>'"]/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#039;','"':'&quot;'}[character]));
        }

        function copyNodeConfig(event, tag) {
            event.stopPropagation();
            const node = nodesCache.find(n => n.tag === tag);
            if (!node) return showToast('未找到对应落地节点', 'error');
            if (!node.is_ix_route) return showToast('该节点当前仅用于 IXR 调度，请先在节点编辑中启用 IX 线路', 'error');
            if (!node.frontend_uuid) return showToast('请先为该落地节点绑定前端用户', 'error');

            const config = {
                v: "2",
                ps: `HKIX|${node.tag}-${node.config_ip}`,
                add: frontEntryHost,
                port: String(currentInboundPort || "10183"),
                id: node.frontend_uuid,
                aid: "0",
                scy: "auto",
                net: "tcp",
                type: "none",
                host: "",
                path: "",
                tls: "",
                sni: "",
                alpn: "",
                fp: "",
                insecure: "0"
            };
            const link = `vmess://${encodeBase64Utf8(JSON.stringify(config, null, 2))}`;
            navigator.clipboard.writeText(link).then(() => {
                showToast(`已复制 ${node.tag} 的本地客户端配置`, 'success');
            }).catch(err => {
                showToast('复制失败，请手动选择复制', 'error');
            });
        }

        function copySubscriptionUrl() {
            openSubscriptionModal();
        }

        function openSubscriptionModal() {
            const modal = document.getElementById('subscriptionModal');
            const card = document.getElementById('subscriptionModalCard');
            modal.classList.remove('hidden');
            modal.classList.add('flex');
            setTimeout(() => { modal.classList.remove('opacity-0'); card.classList.add('modal-enter'); }, 10);
        }

        function closeSubscriptionModal() {
            const modal = document.getElementById('subscriptionModal');
            const card = document.getElementById('subscriptionModalCard');
            modal.classList.add('opacity-0');
            card.classList.remove('modal-enter');
            setTimeout(() => { modal.classList.add('hidden'); modal.classList.remove('flex'); }, 250);
        }

        function copyVmessSubscription() {
            copySubscriptionLink(SUB_URL, 'VMess');
        }

        function copySurgeSubscription() {
            copySubscriptionLink(SURGE_SUB_URL, 'Surge');
        }

        function copySubscriptionLink(url, label) {
            navigator.clipboard.writeText(url).then(() => {
                closeSubscriptionModal();
                showToast(label + ' 订阅链接已复制');
            }).catch(() => showToast('复制失败，请手动选择复制', 'error'));
        }

        function wait(milliseconds) {
            return new Promise(resolve => setTimeout(resolve, milliseconds));
        }

        async function requestJson(url, options = {}) {
            let response;
            try {
                response = await fetch(url, {
                    cache: 'no-store',
                    credentials: 'same-origin',
                    ...options
                });
            } catch (error) {
                const networkError = new Error('连接短暂中断');
                networkError.cause = error;
                networkError.isNetworkError = true;
                throw networkError;
            }
            const responseText = await response.text();
            let payload;
            try {
                payload = responseText ? JSON.parse(responseText) : {};
            } catch (error) {
                const responseError = new Error(`接口返回异常 (${response.status})`);
                responseError.status = response.status;
                throw responseError;
            }
            if (!response.ok || payload.success === false) {
                const responseError = new Error(payload.error || payload.message || `请求失败 (${response.status})`);
                responseError.status = response.status;
                responseError.payload = payload;
                throw responseError;
            }
            return payload;
        }

        function vmessNodeTag(uri) {
            try {
                if (!uri.startsWith('vmess://')) return '';
                let encoded = uri.slice(8).trim().replace(/-/g, '+').replace(/_/g, '/');
                encoded += '='.repeat((4 - encoded.length % 4) % 4);
                const bytes = Uint8Array.from(atob(encoded), character => character.charCodeAt(0));
                const payload = JSON.parse(new TextDecoder('utf-8').decode(bytes));
                return String(payload.ps || '').replace(/[^A-Za-z0-9_-]+/g, '');
            } catch (error) {
                return '';
            }
        }

        async function confirmNodeState(tag, expectedExists, attempts = 15) {
            for (let attempt = 0; attempt < attempts; attempt += 1) {
                try {
                    const data = await loadData();
                    const exists = (data.nodes || []).some(node => node.tag === tag);
                    if (exists === expectedExists) return true;
                } catch (error) {
                }
                await wait(800 + Math.min(attempt, 4) * 250);
            }
            return false;
        }

        async function loadData() {
            const response = await fetch(`?api=get_data&_=${Date.now()}`, {
                cache: 'no-store',
                credentials: 'same-origin'
            });
            const res = await response.json();
            if (!response.ok) throw new Error(res.error || `加载节点数据失败 (${response.status})`);
            clientsCache = res.clients;
            nodesCache = res.nodes;
            currentInboundPort = res.inbound_port;
            frontEntryHost = res.front_entry_host || frontEntryHost;
            document.getElementById('inboundPort').textContent = res.inbound_port;
            document.getElementById('frontEntryHost').textContent = frontEntryHost;
            const frontHostInput = document.getElementById('frontEntryHostInput');
            if (frontHostInput) frontHostInput.value = frontEntryHost;
            const portInput = document.getElementById('sharedInboundPortInput');
            if (portInput) portInput.value = res.inbound_port || '';

            const metric = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value; };
            metric('ixNodeCount', (res.nodes || []).length);
            metric('ixRouteCount', res.ix_route_count ?? (res.nodes || []).filter(node => node.is_ix_route).length);
            metric('ixrOnlyCount', res.ixr_only_count ?? (res.nodes || []).filter(node => !node.is_ix_route).length);
            metric('ixClientCount', (res.clients || []).length);
            metric('ixInboundMetric', res.inbound_port || '--');

            const emailCounts = {};
            const bindings = res.bindings || {};
            Object.values(bindings).forEach(email => { if (email) emailCounts[email] = (emailCounts[email] || 0) + 1; });

            const nodeRows = (res.nodes || []).map(node => {
                const tagKey = encodeURIComponent(node.tag);
                const currentBinding = bindings[node.tag] || '';
                const isDuplicate = currentBinding !== '' && emailCounts[currentBinding] > 1;
                const options = clientsCache.map(c => `<option value="${escapeHtml(c.email)}" ${c.email === currentBinding ? 'selected' : ''}>${escapeHtml(c.email)}</option>`).join('');

                const selectClasses = isDuplicate
                    ? 'border-red-300 focus:ring-red-500 bg-red-50 text-red-700'
                    : 'border-slate-200 focus:ring-indigo-500 bg-slate-50 text-slate-700 hover:bg-white';

                const warningMsg = isDuplicate ? `<div class="text-xs text-red-500 mt-2 font-medium flex items-center"><i class="fa-solid fa-triangle-exclamation mr-1.5"></i>已绑定其他节点</div>` : '';

                const exitIpStatus = String(node.exit_ip || '待探测');
                const isError = exitIpStatus.includes("超时") || exitIpStatus.includes("未分配") || exitIpStatus.includes("待探测");
                let statusDot = isError ? `<span class="w-2 h-2 rounded-full bg-red-500 mr-1.5 animate-pulse"></span>` : `<span class="w-2 h-2 rounded-full bg-emerald-500 mr-1.5"></span>`;
                let exitIpColor = isError ? "text-slate-500" : "text-emerald-600 font-bold";
                let probeClass = node.probe_result === '一致' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : (node.probe_result === '不一致' ? 'bg-red-50 text-red-700 border-red-200' : 'bg-slate-100 text-slate-500 border-slate-200');
                const typeBadge = node.is_ix_route
                    ? '<span class="node-type-badge ix"><i class="fa-solid fa-route"></i>IX 线路</span>'
                    : '<span class="node-type-badge ixr"><i class="fa-solid fa-shuffle"></i>IXR 专用</span>';
                const bindingControl = node.is_ix_route ? `
                    <select onchange="updateBinding(decodeURIComponent('${tagKey}'), this.value)" class="border rounded-xl block w-full px-3 py-2 outline-none transition cursor-pointer text-sm font-medium ${selectClasses}">
                        <option value="">-- 未绑定 (阻断连接) --</option>
                        ${options}
                    </select>
                    ${warningMsg}` : `
                    <div class="rounded-xl border border-blue-100 bg-blue-50 px-3 py-3 text-sm text-blue-700">
                        <div class="font-bold"><i class="fa-solid fa-shuffle mr-1.5"></i>仅参与 IXR 出口调度</div>
                        <button type="button" onclick="promoteNode(decodeURIComponent('${tagKey}'))" class="mt-2 text-xs font-bold text-indigo-600 hover:text-indigo-800">启用 IX 线路</button>
                    </div>`;

                return `<tr class="hover:bg-indigo-50/60 transition-colors cursor-pointer group border-b border-transparent hover:border-indigo-100" onclick="copyNodeConfig(event, decodeURIComponent('${tagKey}'))">
                    <td class="px-5 py-4 whitespace-nowrap">
                        <div class="flex items-center gap-2 mb-1">${typeBadge}<span class="text-xs text-slate-400 font-mono">${escapeHtml(node.network || 'tcp')}${node.tls ? '+' + escapeHtml(node.tls) : ''}</span></div>
                        <div class="font-bold text-slate-800 text-[15px] group-hover:text-indigo-600 hover:bg-indigo-100 inline-block px-1.5 py-1 rounded transition-colors -ml-1.5" onclick="event.stopPropagation(); openNodeModal(decodeURIComponent('${tagKey}'))" title="点击编辑完整出口配置">${escapeHtml(node.tag)}</div>
                        <div class="font-mono text-[12px] text-slate-500 mt-1 opacity-80">
                            <span class="hover:text-indigo-600 hover:bg-indigo-100 px-1.5 py-1 rounded transition-colors -ml-1.5 inline-block" onclick="copyText(event, '${escapeHtml(node.uuid)}')" title="点击仅复制落地 UUID">${escapeHtml(node.uuid)}</span>
                        </div>
                    </td>
                    <td class="px-5 py-4 whitespace-nowrap text-sm">
                        <div class="text-slate-500 mb-1.5 flex items-center">
                            <i class="fa-solid fa-arrow-right-to-bracket text-slate-300 mr-2 w-4"></i>
                            <span class="font-mono">${escapeHtml(node.config_ip)}:${escapeHtml(node.config_port)} · <span class="font-bold text-slate-700">${escapeHtml(node.latency)}</span></span>
                        </div>
                        <div class="flex items-center text-sm">
                            <i class="fa-solid fa-globe text-slate-300 mr-2 w-4"></i>
                            ${statusDot}
                            <span class="font-mono ${exitIpColor}">${escapeHtml(exitIpStatus)}</span>
                            <span class="ml-2 px-2 py-0.5 rounded-full border text-[11px] font-bold ${probeClass}">${escapeHtml(node.probe_result)}</span>
                        </div>
                        <div class="text-xs text-slate-400 mt-2"><i class="fa-solid fa-magnifying-glass mr-1.5"></i>127.0.0.1:${escapeHtml(node.probe_port || '--')}</div>
                    </td>
                    <td class="px-5 py-4" onclick="event.stopPropagation()">
                        ${bindingControl}
                    </td>
                    <td class="px-5 py-4 text-center whitespace-nowrap" onclick="event.stopPropagation()">
                        <button type="button" onclick="deleteNode(event, decodeURIComponent('${tagKey}'))" class="text-slate-400 hover:text-red-500 hover:bg-red-50 p-2.5 rounded-xl transition-all outline-none" title="彻底删除此节点">
                            <i class="fa-solid fa-trash-can"></i>
                        </button>
                    </td>
                </tr>`;
            }).join('');
            document.getElementById('nodeTable').innerHTML = nodeRows || '<tr><td colspan="4" class="px-5 py-12 text-center text-slate-400">暂无出口节点</td></tr>';

            // 右侧列表：精准点击 UUID 进行复制，拦截弹窗冒泡
            document.getElementById('clientTable').innerHTML = res.clients.map(c => `
                <tr class="hover:bg-purple-50/60 transition-colors cursor-pointer group" onclick="openClientModal('${c.email}', '${c.id}')" title="点击编辑用户信息">
                    <td class="px-5 py-4 text-sm font-medium text-slate-700 whitespace-nowrap group-hover:text-purple-600 transition-colors">
                        ${c.email}
                    </td>
                    <td class="px-5 py-4 font-mono text-[13px] text-slate-500 whitespace-nowrap opacity-80 group-hover:opacity-100 transition-opacity">
                        <span class="hover:text-purple-600 hover:bg-purple-100 px-1.5 py-1 rounded transition-colors inline-block" onclick="copyText(event, '${c.id}')" title="点击仅复制 UUID">${c.id}</span>
                    </td>
                </tr>
            `).join('');
            return res;
        }

        function setSelectValue(id, value) {
            const select = document.getElementById(id);
            const normalized = String(value ?? '');
            if (![...select.options].some(option => option.value === normalized)) select.add(new Option(normalized, normalized));
            select.value = normalized;
        }

        function syncNodeTypeControls() {
            const enabled = document.getElementById('modalEnableIx').checked;
            const badge = document.getElementById('modalNodeType');
            const frontWrap = document.getElementById('modalShowOnFrontWrap');
            const frontToggle = document.getElementById('modalShowOnFront');
            badge.className = `node-type-badge ${enabled ? 'ix' : 'ixr'}`;
            badge.innerHTML = enabled ? '<i class="fa-solid fa-route"></i>IX 线路' : '<i class="fa-solid fa-shuffle"></i>IXR 专用';
            frontToggle.disabled = !enabled;
            frontWrap.classList.toggle('opacity-50', !enabled);
        }

        function populateNodeModal(node, createMode=false) {
            document.getElementById('modalModeTitle').textContent = createMode ? '手动新增出口节点' : '编辑出口节点';
            document.getElementById('modalOldTag').value = createMode ? '' : (node.tag || '');
            document.getElementById('modalTag').value = node.tag || '';
            document.getElementById('modalProbePort').value = node.probe_port || '';
            document.getElementById('modalAddress').value = node.config_ip || '';
            document.getElementById('modalPort').value = node.config_port || '';
            document.getElementById('modalUuid').value = node.uuid || '';
            document.getElementById('modalAid').value = node.aid ?? 0;
            document.getElementById('modalSecurity').value = node.security || 'auto';
            setSelectValue('modalNetwork', node.network || 'tcp');
            document.getElementById('modalHeaderType').value = node.header_type || 'none';
            setSelectValue('modalTls', node.tls || '');
            setSelectValue('modalInsecure', String(node.insecure || '0') === '1' ? '1' : '0');
            document.getElementById('modalHost').value = node.host || '';
            document.getElementById('modalPath').value = node.path || '';
            document.getElementById('modalSni').value = node.sni || '';
            document.getElementById('modalAlpn').value = node.alpn || '';
            document.getElementById('modalFp').value = node.fp || '';
            document.getElementById('modalEnableIx').checked = createMode ? true : node.is_ix_route === true;
            document.getElementById('modalShowOnFront').checked = createMode ? true : node.show_on_front === true;
            syncNodeTypeControls();
            const m = document.getElementById('nodeModal'); const c = document.getElementById('nodeModalCard');
            m.classList.remove('hidden'); m.classList.add('flex');
            setTimeout(() => { m.classList.remove('opacity-0'); c.classList.add('modal-enter'); }, 10);
        }

        function openNodeModal(tag) {
            const node = nodesCache.find(item => item.tag === tag);
            if (!node) return showToast('未找到对应出口节点', 'error');
            populateNodeModal(node, false);
        }

        function openCreateNodeModal() {
            populateNodeModal({aid:0, security:'auto', network:'tcp', header_type:'none', tls:'', insecure:'0'}, true);
        }

        function promoteNode(tag) {
            openNodeModal(tag);
            document.getElementById('modalEnableIx').checked = true;
            document.getElementById('modalShowOnFront').checked = true;
            syncNodeTypeControls();
        }

        function closeNodeModal() {
            const m = document.getElementById('nodeModal'); const c = document.getElementById('nodeModalCard');
            m.classList.add('opacity-0'); c.classList.remove('modal-enter');
            setTimeout(() => { m.classList.add('hidden'); m.classList.remove('flex'); }, 300);
        }

        async function saveNodeModal() {
            const oldTag = document.getElementById('modalOldTag').value;
            const payload = {
                old_tag: oldTag,
                name: document.getElementById('modalTag').value.trim(),
                probe_port: document.getElementById('modalProbePort').value.trim(),
                address: document.getElementById('modalAddress').value.trim(),
                remote_port: document.getElementById('modalPort').value.trim(),
                id: document.getElementById('modalUuid').value.trim(),
                aid: document.getElementById('modalAid').value.trim(),
                security: document.getElementById('modalSecurity').value.trim(),
                network: document.getElementById('modalNetwork').value.trim(),
                header_type: document.getElementById('modalHeaderType').value.trim(),
                tls: document.getElementById('modalTls').value.trim(),
                insecure: document.getElementById('modalInsecure').value,
                host: document.getElementById('modalHost').value.trim(),
                path: document.getElementById('modalPath').value.trim(),
                sni: document.getElementById('modalSni').value.trim(),
                alpn: document.getElementById('modalAlpn').value.trim(),
                fp: document.getElementById('modalFp').value.trim(),
                enable_ix: document.getElementById('modalEnableIx').checked,
                show_on_front: document.getElementById('modalShowOnFront').checked
            };
            if (!payload.name) return showToast('出口名称不能为空', 'error');
            if (!payload.address) return showToast('服务器地址不能为空', 'error');
            if (!payload.remote_port) return showToast('远端端口不能为空', 'error');
            if (!payload.id) return showToast('用户 ID / UUID 不能为空', 'error');
            const button = document.getElementById('modalSaveButton');
            const originalHtml = button.innerHTML;
            button.disabled = true;
            button.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i>正在应用...';
            try {
                const action = oldTag ? 'edit_node' : 'create_node';
                const res = await requestJson(`?api=${action}&_=${Date.now()}`, {
                    method: 'POST',
                    headers: {'Accept':'application/json','Content-Type':'application/json'},
                    body: JSON.stringify(payload)
                });
                closeNodeModal();
                showToast(res.message || '出口配置已保存');
                await loadData();
            } catch (error) {
                showToast(error.message || '出口配置保存失败', 'error');
            } finally {
                button.disabled = false;
                button.innerHTML = originalHtml;
            }
        }

        function openClientModal(email, uuid) {
            document.getElementById('modalClientEmailDisplay').textContent = email;
            document.getElementById('modalClientEmail').value = email;
            document.getElementById('modalClientUuid').value = uuid;
            const m = document.getElementById('clientModal'); const c = document.getElementById('clientModalCard');
            m.classList.remove('hidden'); m.classList.add('flex');
            setTimeout(() => { m.classList.remove('opacity-0'); c.classList.add('modal-enter'); }, 10);
        }
        function closeClientModal() {
            const m = document.getElementById('clientModal'); const c = document.getElementById('clientModalCard');
            m.classList.add('opacity-0'); c.classList.remove('modal-enter');
            setTimeout(() => { m.classList.add('hidden'); m.classList.remove('flex'); }, 300);
        }
        async function saveClientModal() {
            const email = document.getElementById('modalClientEmail').value;
            const newUuid = document.getElementById('modalClientUuid').value;
            closeClientModal();
            const res = await fetch('?api=edit_client_uuid', {method: 'POST', body: JSON.stringify({email: email, new_uuid: newUuid})}).then(r => r.json());
            if(res.success) { showToast(res.message); loadData(); } else showToast(res.error, "error");
        }

        function openPasswordModal() {
            ['currentPass', 'newPass', 'confirmPass'].forEach(id => document.getElementById(id).value = '');
            const m = document.getElementById('passwordModal'); const c = document.getElementById('passwordModalCard');
            m.classList.remove('hidden'); m.classList.add('flex');
            setTimeout(() => { m.classList.remove('opacity-0'); c.classList.add('modal-enter'); }, 10);
        }
        function closePasswordModal() {
            const m = document.getElementById('passwordModal'); const c = document.getElementById('passwordModalCard');
            m.classList.add('opacity-0'); c.classList.remove('modal-enter');
            setTimeout(() => { m.classList.add('hidden'); m.classList.remove('flex'); }, 300);
        }
        async function savePasswordModal() {
            const currentPass = document.getElementById('currentPass').value;
            const newPass = document.getElementById('newPass').value;
            const confirmPass = document.getElementById('confirmPass').value;
            if (!currentPass || !newPass || !confirmPass) return showToast('请完整填写密码', 'error');
            if (newPass !== confirmPass) return showToast('两次输入的新密码不一致', 'error');
            const res = await fetch('?api=change_password', {method: 'POST', body: JSON.stringify({current_pass: currentPass, new_pass: newPass, confirm_pass: confirmPass})}).then(r => r.json());
            if(res.success) { closePasswordModal(); showToast(res.message); } else showToast(res.error, "error");
        }

        // --- 其他原逻辑 ---
        async function saveSharedInboundPort() {
            const input = document.getElementById('sharedInboundPortInput');
            const value = (input.value || '').trim();
            const port = Number(value);
            if (!/^\d+$/.test(value) || !Number.isInteger(port) || port < 1 || port > 65535)
                return showToast('监听端口必须为 1–65535 的整数', 'error');
            if (port === Number(currentInboundPort)) return showToast('端口未变更');
            if (!confirm(`将 Xray 共享监听端口修改为 ${port}？已有客户端及前置转发需要同步调整。`)) return;
            const button = document.getElementById('saveSharedInboundPortBtn');
            button.disabled = true;
            try {
                const response = await fetch('?api=edit_inbound_port', {
                    method: 'POST', credentials: 'same-origin',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({new_port: port})
                });
                const result = await response.json();
                if (!response.ok || !result.success) throw new Error(result.error || '保存端口失败');
                showToast(result.message); await loadData();
            } catch (error) { showToast(error.message, 'error'); }
            finally { button.disabled = false; }
        }

        async function editInboundPort() {
            const input = prompt(`修改主监听端口\n\n⚠️ 请确保服务器防火墙已放行新端口。\n\n输入 1-65535 之间的数字：`, currentInboundPort);
            if (input === null || input.trim() === '' || input.trim() == currentInboundPort) return;
            const res = await fetch('?api=edit_inbound_port', {method: 'POST', body: JSON.stringify({new_port: input.trim()})}).then(r => r.json());
            if(res.success) { showToast(res.message); loadData(); } else showToast(res.error, "error");
        }

        async function editFrontEntryHost() {
            const inputBox = document.getElementById('frontEntryHostInput');
            if (inputBox) {
                inputBox.focus();
                inputBox.select();
                showToast('已定位到连接地址设置，修改后点击保存地址');
                return;
            }
            const input = prompt(`修改导出 VMess 的连接地址\n\n只填写域名或 IP，不要带 https://、端口或路径。\n\n例如：your-forward-domain.com`, frontEntryHost);
            if (input === null || input.trim() === '' || input.trim() === frontEntryHost) return;
            await saveFrontEntryHost(input.trim());
        }

        async function saveFrontEntryHostFromInput() {
            const input = document.getElementById('frontEntryHostInput');
            if (!input) return;
            const value = input.value.trim();
            if (!value) return showToast('请先填写导出连接地址', 'error');
            if (value === frontEntryHost) return showToast('连接地址没有变化');
            await saveFrontEntryHost(value);
        }

        async function saveFrontEntryHost(value) {
            const res = await fetch('?api=edit_front_entry_host', {method: 'POST', body: JSON.stringify({front_entry_host: value})}).then(r => r.json());
            if(res.success) { frontEntryHost = res.front_entry_host; showToast(`${res.message}，复制配置会立即使用新地址`); loadData(); } else showToast(res.error, "error");
            return res;
        }

        async function updateBinding(tag, email) {
            const res = await fetch('?api=update_binding', {method: 'POST', body: JSON.stringify({tag, email})}).then(r => r.json());
            if(res.success) { showToast(res.message || '路由调度已同步到 Xray'); loadData(); }
        }

        async function addNode(event) {
            event.preventDefault();
            if (addNodePending) return;
            const input = document.getElementById('vmessInput');
            const uri = input.value.trim();
            if(!uri) return showToast('请输入 vmess 链接', "error");
            const tag = vmessNodeTag(uri);
            const enableIx = document.getElementById('importEnableIx').checked;
            const button = event.currentTarget || document.getElementById('addNodeBtn');
            const originalHtml = button.innerHTML;
            addNodePending = true;
            button.disabled = true;
            button.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i>正在添加...';
            button.classList.add('opacity-60', 'cursor-wait');
            try {
                const res = await requestJson(`?api=add_node_from_uri&_=${Date.now()}`, {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({uri, enable_ix: enableIx})
                });
                input.value = '';
                showToast(res.message || '节点添加成功');
                if (tag) {
                    await confirmNodeState(tag, true, 8);
                } else {
                    await loadData();
                }
            } catch (error) {
                if (error.isNetworkError && tag) {
                    showToast('连接短暂中断，正在确认节点是否已添加', 'info');
                    if (await confirmNodeState(tag, true)) {
                        input.value = '';
                        showToast(`节点 ${tag} 已添加，列表已刷新`);
                        return;
                    }
                }
                showToast(error.message || '节点添加失败，请重试', 'error');
            } finally {
                addNodePending = false;
                button.disabled = false;
                button.innerHTML = originalHtml;
                button.classList.remove('opacity-60', 'cursor-wait');
            }
        }

        async function deleteNode(event, tag) {
            event.preventDefault();
            event.stopPropagation();
            if(!confirm(`⚠️ 危险操作\n\n确定彻底删除 [ ${tag} ] 出口吗？相关 IX 线路、用户授权、自动池和端口规则引用会一起移除。`)) return;
            const button = event.currentTarget;
            const originalHtml = button.innerHTML;
            button.disabled = true;
            button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
            button.classList.add('opacity-60', 'cursor-wait');
            try {
                const res = await requestJson(`?api=delete_node&_=${Date.now()}`, {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({tag})
                });
                showToast(res.message || `节点 ${tag} 已删除`);
                await confirmNodeState(tag, false, 8);
            } catch (error) {
                showToast('正在确认删除结果，请稍候', 'info');
                if (await confirmNodeState(tag, false)) {
                    showToast(`节点 ${tag} 已删除，列表已刷新`);
                    return;
                }
                showToast(error.message || '删除失败，请重试', 'error');
            } finally {
                button.disabled = false;
                button.innerHTML = originalHtml;
                button.classList.remove('opacity-60', 'cursor-wait');
            }
        }

        async function restartService() {
            const btn = document.getElementById('rebootBtn');
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i>处理中...';
            btn.disabled = true; btn.classList.add('opacity-70', 'cursor-wait');
            try {
                const res = await fetch('?api=restart_service', {method: 'POST'}).then(r => r.json());
                if(res.success) showToast(res.message); else showToast(res.error, "error");
            } catch (err) {
                showToast(`后台重启指令已发送，连接闪断属于正常现象`, "success");
            } finally {
                setTimeout(() => { btn.innerHTML = originalHtml; btn.disabled = false; btn.classList.remove('opacity-70', 'cursor-wait'); }, 1500);
            }
        }

        async function testNodeIps() {
            const btn = document.getElementById('testIpBtn');
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="fa-solid fa-satellite-dish fa-spin mr-2"></i>探测中...';
            btn.disabled = true; btn.classList.add('opacity-70', 'cursor-wait');
            try {
                const res = await fetch('?api=test_node_ips', {method: 'POST'}).then(r => r.json());
                if(res.success) { showToast(res.message); loadData(); } else showToast(res.error, "error");
            } catch (err) {
                showToast(`接口请求超时，请检查服务状态`, "error");
            } finally {
                btn.innerHTML = originalHtml; btn.disabled = false; btn.classList.remove('opacity-70', 'cursor-wait');
            }
        }

        function showToast(msg, type="success") {
            const t = document.getElementById('toast');
            const icon = type === 'success' ? '<i class="fa-solid fa-circle-check text-xl"></i>' : (type === 'info' ? '<i class="fa-solid fa-spinner fa-spin text-xl"></i>' : '<i class="fa-solid fa-circle-xmark text-xl"></i>');
            const bgClass = type === 'success' ? 'bg-slate-800/95 border-emerald-500/50 text-white' : (type === 'info' ? 'bg-blue-600/95 border-blue-400 text-white shadow-blue-500/30' : 'bg-red-500/95 border-red-400 text-white shadow-red-500/30');
            t.innerHTML = `${icon} <span>${msg}</span>`;
            t.className = `fixed bottom-8 right-8 transform translate-y-0 opacity-100 transition-all duration-400 ease-out px-6 py-4 rounded-2xl shadow-2xl z-50 flex items-center gap-3 font-medium max-w-md pointer-events-none border backdrop-blur-xl ${bgClass}`;
            setTimeout(() => { t.classList.replace('translate-y-0', 'translate-y-12'); t.classList.replace('opacity-100', 'opacity-0'); }, 3500);
        }

        loadData().catch(error => showToast(error.message || '节点数据加载失败', 'error'));
    </script>
</body>
</html>
