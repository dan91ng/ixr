<?php
declare(strict_types=1);

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('Referrer-Policy: same-origin');

session_start();
require_once __DIR__ . '/lib/user_store.php';

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
    header('Location: /admin.php');
    exit;
}

function ua_h(mixed $value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function ua_redirect(int $userId = 0): never
{
    header('Location: /users-admin.php' . ($userId > 0 ? '#user-' . $userId : ''));
    exit;
}

function ua_set_flash(string $message, string $kind = 'ok'): void
{
    $_SESSION['ixr_user_admin_flash'] = ['message' => $message, 'kind' => $kind];
}

function ua_error_message(Throwable $error): string
{
    $message = $error->getMessage();
    if (str_contains($message, 'UNIQUE constraint failed: users.username')) {
        return '用户名已存在';
    }
    if (str_contains($message, 'UNIQUE constraint failed: user_ports.user_id, user_ports.port')) {
        return '该用户已拥有所选 IXR 端口，请刷新页面后重试';
    }
    if (str_contains($message, 'UNIQUE constraint failed: user_routes.xray_email')) {
        return 'IX 线路凭证生成冲突，请重试';
    }
    return $message !== '' ? $message : '操作失败';
}

$databaseError = '';
$database = null;
try {
    $database = ixr_user_db();
} catch (Throwable $error) {
    $databaseError = $error->getMessage();
}

$actor = (string)(getenv('IXR_ADMIN_USER') ?: 'admin');

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $database instanceof PDO) {
    $userId = max(0, (int)($_POST['user_id'] ?? 0));
    try {
        if (!ixr_verify_csrf((string)($_POST['csrf'] ?? ''))) {
            throw new RuntimeException('页面已过期，请刷新后重试');
        }
        $action = (string)($_POST['action'] ?? '');
        if ($action === 'create') {
            $userId = ixr_create_user($database, $_POST, $actor);
            ixr_schedule_apply('创建 IXR 用户 #' . $userId);
            ua_set_flash('用户创建成功，IXR 与 IX 授权正在后台应用');
        } elseif ($action === 'update') {
            if ($userId <= 0) {
                throw new InvalidArgumentException('用户编号无效');
            }
            ixr_update_user($database, $userId, $_POST, $actor);
            ixr_schedule_apply('更新 IXR 用户 #' . $userId);
            ua_set_flash('用户资料已保存，IXR 与 IX 授权正在后台应用');
        } elseif ($action === 'reset_usage') {
            if ($userId <= 0) {
                throw new InvalidArgumentException('用户编号无效');
            }
            ixr_reset_user_usage($database, $userId, $actor);
            ixr_schedule_runtime_sync('重置 IXR 用户流量 #' . $userId);
            ua_set_flash('用户累计流量已清零，额度状态正在无重启恢复');
        } elseif ($action === 'rotate_token') {
            if ($userId <= 0) {
                throw new InvalidArgumentException('用户编号无效');
            }
            ixr_rotate_subscription_token($database, $userId, $actor);
            ua_set_flash('订阅 Token 已重置，旧订阅链接立即失效');
        } elseif ($action === 'delete') {
            if ($userId <= 0) {
                throw new InvalidArgumentException('用户编号无效');
            }
            ixr_delete_user($database, $userId, $actor);
            ua_set_flash('用户已删除');
            $userId = 0;
        } else {
            throw new InvalidArgumentException('未知操作');
        }
    } catch (Throwable $error) {
        ua_set_flash(ua_error_message($error), 'error');
    }
    ua_redirect($userId);
}

$flash = $_SESSION['ixr_user_admin_flash'] ?? null;
unset($_SESSION['ixr_user_admin_flash']);

$users = [];
$catalog = [];
$routeCatalog = [];
$owners = [];
$assignedPorts = 0;
$assignedRoutes = 0;
if ($database instanceof PDO) {
    try {
        $users = ixr_list_users($database);
        $catalog = ixr_state_catalog();
        $routeCatalog = ixr_ix_route_catalog();
        $owners = ixr_active_port_owners($database);
        $assignedPorts = ixr_active_port_assignment_count($database);
        $assignedRoutes = ixr_active_route_assignment_count($database);
    } catch (Throwable $error) {
        $databaseError = $error->getMessage();
    }
}

$activeUsers = count(array_filter($users, static fn(array $user): bool => $user['status'] === 'active'));
$csrf = ixr_csrf_token();
?>
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>用户与配额 | 线路管理</title>
    <style>
        :root{--bg:#f4f7fb;--card:#fff;--text:#172033;--muted:#64748b;--line:#dfe6f0;--blue:#2563eb;--green:#15803d;--red:#dc2626;--amber:#d97706;--shadow:0 14px 34px #1f293714}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",Arial,"Microsoft YaHei",sans-serif}.shell{min-height:100vh}.side{position:fixed;inset:0 auto 0 0;width:250px;background:#0f172a;color:#fff;padding:24px 18px;display:flex;flex-direction:column;gap:22px;overflow-y:auto}.brand{font-size:24px;font-weight:900}.brand small{display:block;color:#94a3b8;font-size:12px;margin-top:4px}.nav{display:grid;gap:8px}.nav a{color:#dbeafe;text-decoration:none;border-radius:12px;padding:11px 12px;font-weight:800}.nav a:hover,.nav a.active{background:#1e293b;color:#fff}.side-foot{margin-top:auto;display:grid;gap:10px;color:#cbd5e1;font-size:13px}.main{margin-left:250px;padding:28px;max-width:1600px}.hero{padding:24px;border-radius:22px;background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;box-shadow:0 18px 40px #1f293722}.hero h1{margin:0 0 7px}.hero p{margin:0;color:#e0e7ff}.summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:16px}.metric,.card{background:var(--card);border:1px solid #edf1f7;border-radius:18px;box-shadow:var(--shadow)}.metric{padding:16px}.metric span{display:block;color:var(--muted);font-size:13px}.metric b{font-size:28px}.card{padding:20px;margin-top:18px}.section-head{display:flex;justify-content:space-between;gap:14px;align-items:center;flex-wrap:wrap}.section-head h2,.section-head h3{margin:0}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.field label,.ports-title{display:block;font-size:13px;font-weight:800;color:#334155;margin-bottom:6px}.field input{width:100%;border:1px solid var(--line);border-radius:11px;padding:10px 11px;font:inherit;background:#fff}.check{display:flex;align-items:center;gap:8px;font-size:14px;font-weight:800}.check input{width:18px;height:18px}.ports{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:9px;margin:8px 0 16px}.port{border:1px solid var(--line);border-radius:12px;padding:10px;background:#f8fafc;display:flex;gap:9px;align-items:flex-start}.port.owned{border-color:#93c5fd;background:#eff6ff}.port.busy{opacity:.58}.port.shared{border-style:dashed}.port input{width:18px;height:18px;margin-top:2px}.port small{display:block;color:var(--muted);margin-top:3px}.btn{display:inline-flex;align-items:center;justify-content:center;border:0;border-radius:11px;padding:10px 14px;background:var(--blue);color:#fff;text-decoration:none;font:inherit;font-weight:900;cursor:pointer}.btn.secondary{background:#eef2ff;color:#3730a3}.btn.green{background:var(--green)}.btn.red{background:var(--red)}.actions{display:flex;flex-wrap:wrap;gap:9px;align-items:center}.actions form{margin:0}.flash{border-left:6px solid var(--green)}.flash.error{border-left-color:var(--red);color:#991b1b}.status{display:inline-flex;border-radius:999px;padding:5px 10px;font-size:12px;font-weight:900}.status.active{background:#dcfce7;color:#166534}.status.disabled,.status.expired,.status.quota_exhausted{background:#fee2e2;color:#991b1b}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:14px 0}.stat{padding:11px;border-radius:12px;background:#f8fafc;border:1px solid #e2e8f0}.stat span{display:block;color:var(--muted);font-size:12px}.stat b{font-size:16px}.links{display:grid;gap:8px;margin:12px 0}.link-row{display:grid;grid-template-columns:90px minmax(0,1fr) auto;gap:8px;align-items:center}.link-row input{min-width:0;width:100%;border:1px solid var(--line);border-radius:10px;padding:9px;background:#f8fafc}.hint{color:var(--muted);font-size:13px}.empty{text-align:center;color:var(--muted);padding:30px}.error-box{background:#fff1f2;border:1px solid #fecdd3;color:#9f1239}.divider{height:1px;background:#e5e7eb;margin:18px 0}.user-card{scroll-margin-top:18px}.user-card:target{outline:3px solid #93c5fd}.top-space{margin-top:14px}@media(max-width:1000px){.side{position:static;width:auto}.main{margin:0;padding:18px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.summary,.stats{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:620px){.grid,.summary,.stats{grid-template-columns:1fr}.link-row{grid-template-columns:1fr}.main{padding:12px}.card{padding:16px}}
    </style>
    <style>
        .nav{gap:16px;align-content:start}.nav-group{display:grid;gap:6px}.nav-parent{padding:0 10px;color:#64748b;font-size:11px;font-weight:900;letter-spacing:.12em}.nav-children{display:grid;gap:4px;padding-left:8px;border-left:1px solid #334155}.nav-children a{padding:9px 10px;font-size:14px}.side-actions{display:grid;grid-template-columns:1fr 1fr;gap:8px}.side-action{display:flex;align-items:center;justify-content:center;min-width:0;border:1px solid #334155;border-radius:10px;padding:9px 8px;color:#dbeafe;text-decoration:none;font-size:12px;font-weight:900;background:#1e293b}.side-action:hover{border-color:#60a5fa;background:#1d4ed8;color:#fff}.side-action.logout{color:#fecaca}.side-action.logout:hover{border-color:#f87171;background:#991b1b}.users-table-card{padding:0;overflow:hidden}.table-scroll{overflow-x:auto}.user-table{width:100%;min-width:1120px;border-collapse:collapse}.user-table th,.user-table td{padding:13px 14px;border-bottom:1px solid #e8edf5;text-align:left;vertical-align:middle}.user-table th{background:#f8fafc;color:#64748b;font-size:12px;font-weight:900;letter-spacing:.04em;white-space:nowrap}.user-summary-row{cursor:pointer;scroll-margin-top:18px;transition:background .15s ease}.user-summary-row:hover td,.user-summary-row.expanded td{background:#f5f8ff}.user-summary-row:focus{outline:0}.user-summary-row:focus td,.user-summary-row:target td{background:#eff6ff}.user-identity{display:grid;gap:3px}.user-identity b{font-size:14px}.user-identity span{color:var(--muted);font-size:12px}.quota-value{white-space:nowrap;font-weight:800}.expiry-value{white-space:nowrap;font-size:13px}.auth-counts{display:flex;gap:6px;flex-wrap:wrap}.auth-count{border-radius:999px;padding:4px 8px;background:#eef2ff;color:#3730a3;font-size:11px;font-weight:900}.btn.compact{padding:7px 11px;font-size:12px}.user-detail-row[hidden]{display:none}.user-detail-cell{padding:0!important;background:#f8fafc}.user-detail-panel{padding:20px 22px 22px;border-bottom:1px solid #dbe4ef}.detail-head{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;margin-bottom:16px}.detail-head h3{margin:0 0 5px}.detail-meta{color:var(--muted);font-size:12px}.user-table tbody:last-child tr:last-child td{border-bottom:0}@media(max-width:1000px){.nav{overflow:visible}.user-detail-panel{padding:18px}}@media(max-width:620px){.side-actions{grid-template-columns:1fr 1fr}.user-detail-panel{padding:16px}}
    </style>
</head>
<body>
<div class="shell">
    <aside class="side">
        <div class="brand">IXR</div>
        <nav class="nav">
            <section class="nav-group"><div class="nav-parent">运行概览</div><div class="nav-children"><a href="/admin.php?section=dashboard">线路总览</a><a href="/admin.php?section=usage">流量统计</a></div></section>
            <section class="nav-group"><div class="nav-parent">线路配置</div><div class="nav-children"><a href="/admin.php?section=ix-admin">统一出口管理</a><a href="/admin.php?section=ports">IXR 端口路由</a><a href="/admin.php?section=pools">IXR 自动出口池</a><a href="/admin.php?section=add-port">新增 IXR 端口</a></div></section>
            <section class="nav-group"><div class="nav-parent">用户管理</div><div class="nav-children"><a class="active" href="/users-admin.php">用户与配额</a></div></section>
            <section class="nav-group"><div class="nav-parent">访问入口</div><div class="nav-children"><a href="/" target="_blank" rel="noopener">线路服务中心</a></div></section>
        </nav>
        <div class="side-foot"><div class="side-actions"><a class="side-action" href="/admin.php?section=account">修改密码</a><a class="side-action logout" href="/admin.php?logout=1">退出登录</a></div></div>
    </aside>
    <main class="main">
        <section class="hero">
            <h1>用户与配额</h1>
        </section>

        <section class="summary">
            <div class="metric"><span>用户总数</span><b><?=ua_h(count($users))?></b></div>
            <div class="metric"><span>正常用户</span><b><?=ua_h($activeUsers)?></b></div>
            <div class="metric"><span>IXR 端口授权次数</span><b><?=ua_h($assignedPorts)?></b></div>
            <div class="metric"><span>IX 线路授权</span><b><?=ua_h($assignedRoutes)?></b></div>
        </section>

        <?php if ($flash): ?>
            <section class="card flash <?=ua_h($flash['kind'] ?? 'ok')?>"><?=ua_h($flash['message'] ?? '')?></section>
        <?php endif; ?>

        <?php if ($databaseError !== ''): ?>
            <section class="card error-box"><b>用户数据库不可用：</b> <?=ua_h($databaseError)?></section>
        <?php else: ?>
            <section class="card">
                <div class="section-head"><h2>创建用户</h2></div>
                <form method="post" class="top-space">
                    <input type="hidden" name="csrf" value="<?=ua_h($csrf)?>">
                    <input type="hidden" name="action" value="create">
                    <div class="grid">
                        <div class="field"><label>用户名</label><input name="username" required minlength="3" maxlength="64" autocomplete="off"></div>
                        <div class="field"><label>显示名称</label><input name="display_name" maxlength="100" placeholder="可留空"></div>
                        <div class="field"><label>初始密码</label><input name="password" type="password" required minlength="8" autocomplete="new-password"></div>
                        <div class="field"><label>流量额度（GB）</label><input name="traffic_limit_gb" type="number" min="0.01" step="0.01" placeholder="留空表示不限额"></div>
                        <div class="field"><label>到期时间</label><input name="expires_at" type="datetime-local"></div>
                        <div class="field"><label>账户状态</label><label class="check"><input name="enabled" type="checkbox" value="1" checked> 启用用户</label></div>
                    </div>
                    <div class="ports-title top-space">分配 IXR 共享端口</div>
                    <div class="ports">
                        <?php foreach ($catalog as $port => $portConfig): $portOwners = $owners[$port] ?? []; $ownerCount = count($portOwners); ?>
                            <label class="port shared <?=$ownerCount > 0 ? 'owned' : ''?>">
                                <input type="checkbox" name="ports[]" value="<?=ua_h($port)?>">
                                <span><b><?=ua_h($portConfig['label'])?></b><small>端口 <?=ua_h($port)?><?=$ownerCount > 0 ? ' · 已有 ' . ua_h($ownerCount) . ' 个用户授权，可继续共享' : ' · 可共享'?></small></span>
                            </label>
                        <?php endforeach; ?>
                    </div>
                    <div class="ports-title top-space">分配 IX 共享线路</div>
                    <?php if (!$routeCatalog): ?>
                        <div class="empty">暂未读取到 IX 线路目录，请检查 IXR/Xray 线路配置。</div>
                    <?php else: ?>
                        <div class="ports">
                            <?php foreach ($routeCatalog as $routeCode => $route): ?>
                                <label class="port shared">
                                    <input type="checkbox" name="routes[]" value="<?=ua_h($routeCode)?>">
                                    <span><b><?=ua_h($route['display_name'])?></b><small><?=ua_h($route['address'])?>:<?=ua_h($route['port'])?> · 共享入口</small></span>
                                </label>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    <button class="btn green" type="submit">创建用户</button>
                </form>
            </section>

            <section class="section-head top-space"><h2>现有用户</h2><span class="hint">点击用户行查看和编辑详情</span></section>

            <?php if (!$users): ?>
                <section class="card empty">尚未创建用户。先在上方创建第一个 IXR 用户。</section>
            <?php else: ?>
                <section class="card users-table-card">
                    <div class="table-scroll">
                        <table class="user-table">
                            <thead><tr><th>用户</th><th>状态</th><th>已用流量</th><th>流量额度</th><th>剩余流量</th><th>到期时间</th><th>线路授权</th><th>操作</th></tr></thead>
                            <tbody>
                            <?php foreach ($users as $user):
                                $userId = (int)$user['id'];
                                $detailId = 'user-detail-' . $userId;
                                $selectedPorts = array_fill_keys(array_map(static fn(array $port): int => (int)$port['port'], $user['ports']), true);
                                $selectedRoutes = array_fill_keys(array_map(static fn(array $route): string => (string)$route['route_code'], $user['routes']), true);
                                $used = (int)$user['traffic_used_bytes'];
                                $limit = $user['traffic_limit_bytes'] === null ? null : (int)$user['traffic_limit_bytes'];
                                $remaining = $limit === null ? null : max(0, $limit - $used);
                            ?>
                                <tr class="user-summary-row" id="user-<?=ua_h($userId)?>" data-user-detail="<?=ua_h($detailId)?>" tabindex="0">
                                    <td><div class="user-identity"><b><?=ua_h($user['display_name'])?></b><span>@<?=ua_h($user['username'])?></span></div></td>
                                    <td><span class="status <?=ua_h($user['status'])?>"><?=ua_h(ixr_status_label((string)$user['status']))?></span></td>
                                    <td class="quota-value"><?=ua_h(ixr_format_bytes($used))?></td>
                                    <td class="quota-value"><?=ua_h(ixr_format_bytes($limit))?></td>
                                    <td class="quota-value"><?=ua_h(ixr_format_bytes($remaining))?></td>
                                    <td class="expiry-value"><?=ua_h($user['expires_at'] ?: '长期有效')?></td>
                                    <td><div class="auth-counts"><span class="auth-count">IXR <?=ua_h(count($user['ports']))?></span><span class="auth-count">IX <?=ua_h(count($user['routes']))?></span></div></td>
                                    <td><button class="btn secondary compact" type="button" data-user-toggle="<?=ua_h($detailId)?>" aria-expanded="false" onclick="toggleUserDetail('<?=ua_h($detailId)?>')">编辑</button></td>
                                </tr>
                                <tr class="user-detail-row" id="<?=ua_h($detailId)?>" hidden>
                                    <td class="user-detail-cell" colspan="8">
                                        <div class="user-detail-panel">
                                            <div class="detail-head"><div><h3>编辑 <?=ua_h($user['display_name'])?></h3><div class="detail-meta">创建于 <?=ua_h($user['created_at'])?>；最后登录 <?=ua_h($user['last_login_at'] ?: '从未登录')?></div></div><span class="status <?=ua_h($user['status'])?>"><?=ua_h(ixr_status_label((string)$user['status']))?></span></div>
                                            <form method="post">
                                                <input type="hidden" name="csrf" value="<?=ua_h($csrf)?>">
                                                <input type="hidden" name="action" value="update">
                                                <input type="hidden" name="user_id" value="<?=ua_h($userId)?>">
                                                <div class="grid">
                                                    <div class="field"><label>显示名称</label><input name="display_name" value="<?=ua_h($user['display_name'])?>" maxlength="100"></div>
                                                    <div class="field"><label>新密码</label><input name="password" type="password" minlength="8" autocomplete="new-password" placeholder="留空则不修改"></div>
                                                    <div class="field"><label>流量额度（GB）</label><input name="traffic_limit_gb" type="number" min="0.01" step="0.01" value="<?=ua_h(ixr_limit_to_gb($limit))?>" placeholder="留空表示不限额"></div>
                                                    <div class="field"><label>到期时间</label><input name="expires_at" type="datetime-local" value="<?=ua_h(ixr_expiry_input($user['expires_at']))?>"></div>
                                                    <div class="field"><label>账户状态</label><label class="check"><input name="enabled" type="checkbox" value="1" <?=((int)$user['enabled'] === 1) ? 'checked' : ''?>> 启用用户</label></div>
                                                </div>
                                                <div class="ports-title top-space">IXR 共享端口</div>
                                                <div class="ports">
                                                    <?php foreach ($catalog as $port => $portConfig):
                                                        $portOwners = $owners[$port] ?? [];
                                                        $isOwn = isset($selectedPorts[$port]);
                                                        $otherOwnerCount = count(array_filter($portOwners, static fn(array $owner): bool => (int)$owner['user_id'] !== $userId));
                                                    ?>
                                                        <label class="port shared <?=$isOwn ? 'owned' : ''?>">
                                                            <input type="checkbox" name="ports[]" value="<?=ua_h($port)?>" <?=$isOwn ? 'checked' : ''?>>
                                                            <span><b><?=ua_h($portConfig['label'])?></b><small>端口 <?=ua_h($port)?><?=$isOwn ? ' · 当前用户已授权' : ' · 可共享'?><?=$otherOwnerCount > 0 ? ' · 另有 ' . ua_h($otherOwnerCount) . ' 个用户' : ''?></small></span>
                                                        </label>
                                                    <?php endforeach; ?>
                                                </div>
                                                <div class="ports-title top-space">IX 共享线路</div>
                                                <?php if (!$routeCatalog): ?>
                                                    <div class="empty">IX 线路目录暂时不可用，保存操作会保留现有线路授权。</div>
                                                <?php else: ?>
                                                    <div class="ports">
                                                        <?php foreach ($routeCatalog as $routeCode => $route): $isOwn = isset($selectedRoutes[$routeCode]); ?>
                                                            <label class="port shared <?=$isOwn ? 'owned' : ''?>">
                                                                <input type="checkbox" name="routes[]" value="<?=ua_h($routeCode)?>" <?=$isOwn ? 'checked' : ''?>>
                                                                <span><b><?=ua_h($route['display_name'])?></b><small><?=ua_h($route['address'])?>:<?=ua_h($route['port'])?><?=$isOwn ? ' · 当前用户' : ' · 可共享'?></small></span>
                                                            </label>
                                                        <?php endforeach; ?>
                                                    </div>
                                                <?php endif; ?>
                                                <button class="btn" type="submit">保存用户设置</button>
                                            </form>

                                            <div class="divider"></div>
                                            <div class="links">
                                                <div class="link-row"><b>VMess</b><input id="vmess-<?=ua_h($userId)?>" readonly value="<?=ua_h(ixr_subscription_url($user, 'v2ray'))?>"><button class="btn secondary" type="button" onclick="copyValue('vmess-<?=ua_h($userId)?>',this)">复制</button></div>
                                                <div class="link-row"><b>Surge</b><input id="surge-<?=ua_h($userId)?>" readonly value="<?=ua_h(ixr_subscription_url($user, 'surge'))?>"><button class="btn secondary" type="button" onclick="copyValue('surge-<?=ua_h($userId)?>',this)">复制</button></div>
                                            </div>
                                            <div class="actions">
                                                <form method="post" onsubmit="return confirm('确定清零该用户的累计流量？')"><input type="hidden" name="csrf" value="<?=ua_h($csrf)?>"><input type="hidden" name="action" value="reset_usage"><input type="hidden" name="user_id" value="<?=ua_h($userId)?>"><button class="btn secondary" type="submit">清零流量</button></form>
                                                <form method="post" onsubmit="return confirm('确定重置订阅 Token？旧链接会立即失效。')"><input type="hidden" name="csrf" value="<?=ua_h($csrf)?>"><input type="hidden" name="action" value="rotate_token"><input type="hidden" name="user_id" value="<?=ua_h($userId)?>"><button class="btn secondary" type="submit">重置订阅链接</button></form>
                                                <form method="post" onsubmit="return confirm('确定删除用户？删除前必须先解除全部 IXR 端口和 IX 线路授权。')"><input type="hidden" name="csrf" value="<?=ua_h($csrf)?>"><input type="hidden" name="action" value="delete"><input type="hidden" name="user_id" value="<?=ua_h($userId)?>"><button class="btn red" type="submit">删除用户</button></form>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </section>
            <?php endif; ?>
        <?php endif; ?>
    </main>
</div>
<script>
async function copyValue(id,button){const input=document.getElementById(id);if(!input)return;try{await navigator.clipboard.writeText(input.value);const old=button.textContent;button.textContent='已复制';setTimeout(()=>button.textContent=old,1400)}catch(error){input.select();document.execCommand('copy')}}
function setUserDetailState(id,open){const detail=document.getElementById(id);if(!detail)return;detail.hidden=!open;document.querySelectorAll('[data-user-toggle]').forEach(button=>{if(button.dataset.userToggle!==id)return;button.setAttribute('aria-expanded',open?'true':'false');button.textContent=open?'收起':'编辑'});const summary=document.querySelector('[data-user-detail="'+id+'"]');if(summary)summary.classList.toggle('expanded',open)}
function toggleUserDetail(id){const detail=document.getElementById(id);if(!detail)return;setUserDetailState(id,detail.hidden)}
document.addEventListener('click',function(event){const row=event.target.closest('.user-summary-row');if(!row||event.target.closest('button,a,input,select,textarea,label,form'))return;toggleUserDetail(row.dataset.userDetail)});
document.addEventListener('keydown',function(event){const row=event.target.closest('.user-summary-row');if(!row||(event.key!=='Enter'&&event.key!==' '))return;event.preventDefault();toggleUserDetail(row.dataset.userDetail)});
function openTargetedUser(){const match=window.location.hash.match(/^#user-(\d+)$/);if(match)setUserDetailState('user-detail-'+match[1],true)}
openTargetedUser();window.addEventListener('hashchange',openTargetedUser);
document.addEventListener('submit',function(event){const form=event.target;if(form.dataset.submitting==='1'){event.preventDefault();return}form.dataset.submitting='1';setTimeout(()=>form.querySelectorAll('button[type="submit"]').forEach(button=>{button.disabled=true;button.style.opacity='.65'}),0)},true);
</script>
</body>
</html>
