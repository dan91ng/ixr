<?php
declare(strict_types=1);

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('Referrer-Policy: no-referrer');

session_start();
require_once __DIR__ . '/lib/user_store.php';

if (isset($_GET['section']) || isset($_GET['port'])) {
    $query = http_build_query($_GET);
    header('Location: /admin.php' . ($query !== '' ? '?' . $query : ''));
    exit;
}

function up_h(mixed $value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

if (isset($_GET['logout'])) {
    unset($_SESSION['ixr_user_id']);
    unset($_SESSION['ixr_user_password_version']);
    header('Location: /');
    exit;
}

$database = null;
$databaseError = '';
try {
    $database = ixr_user_db();
} catch (Throwable $error) {
    $databaseError = $error->getMessage();
}

$loginError = '';
$profileError = '';
$profileSuccess = (string)($_SESSION['ixr_profile_success'] ?? '');
unset($_SESSION['ixr_profile_success']);
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_action']) && $database instanceof PDO) {
    try {
        if (!ixr_verify_csrf((string)($_POST['csrf'] ?? ''))) {
            throw new RuntimeException('页面已过期，请刷新后重试');
        }
        $user = ixr_authenticate_user($database, (string)($_POST['username'] ?? ''), (string)($_POST['password'] ?? ''));
        if (!$user) {
            throw new RuntimeException('用户名或密码不正确');
        }
        session_regenerate_id(true);
        ixr_mark_user_session($user);
        header('Location: /');
        exit;
    } catch (Throwable $error) {
        $loginError = $error->getMessage();
    }
}

$user = null;
$ports = [];
$routes = [];
$nodes = [];
if ($database instanceof PDO && !empty($_SESSION['ixr_user_id'])) {
    try {
        $userId = (int)$_SESSION['ixr_user_id'];
        ixr_sync_user_status($database, $userId);
        $user = ixr_user_by_id($database, $userId);
        if ($user && ixr_user_session_valid($user)) {
            $ports = ixr_user_ports($database, $userId);
            $routes = ixr_user_routes($database, $userId);
            $nodes = ixr_user_nodes($database, $userId);
        } else {
            unset($_SESSION['ixr_user_id']);
            unset($_SESSION['ixr_user_password_version']);
            $user = null;
        }
    } catch (Throwable $error) {
        $databaseError = $error->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['profile_action'])) {
    try {
        if (!($database instanceof PDO) || !$user) {
            throw new RuntimeException('登录状态已失效，请重新登录');
        }
        if (!ixr_verify_csrf((string)($_POST['csrf'] ?? ''))) {
            throw new RuntimeException('页面已过期，请刷新后重试');
        }
        $userId = (int)$user['id'];
        $result = ixr_update_own_profile($database, $userId, $_POST);
        session_regenerate_id(true);
        $updatedUser = ixr_user_by_id($database, $userId);
        if (!$updatedUser) {
            throw new RuntimeException('用户不存在');
        }
        ixr_mark_user_session($updatedUser);
        $_SESSION['ixr_profile_success'] = !empty($result['display_name_changed']) && !empty($result['password_changed'])
            ? '显示名称和密码已更新'
            : (!empty($result['password_changed']) ? '密码已更新' : '显示名称已更新');
        header('Location: /#account');
        exit;
    } catch (Throwable $error) {
        $profileError = $error->getMessage();
    }
}

$csrf = ixr_csrf_token();

if (!$user):
?>
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>线路服务中心登录</title>
    <style>
        *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:radial-gradient(circle at 15% 10%,#60a5fa55,transparent 32%),radial-gradient(circle at 85% 90%,#8b5cf655,transparent 34%),#0f172a;color:#172033;font-family:system-ui,-apple-system,"Segoe UI",Arial,"Microsoft YaHei",sans-serif}.box{width:min(430px,100%);padding:30px;background:#fffffff2;border:1px solid #ffffff88;border-radius:24px;box-shadow:0 28px 80px #02061788;backdrop-filter:blur(16px)}.brand{font-size:14px;font-weight:900;color:#2563eb;letter-spacing:.16em}.box h1{margin:8px 0 6px}.box p{margin:0 0 22px;color:#64748b}.field label{display:block;font-size:13px;font-weight:800;color:#334155}.field input{width:100%;margin:7px 0 16px;border:1px solid #d8deea;border-radius:12px;padding:12px;font:inherit}.btn{width:100%;border:0;border-radius:12px;padding:12px;background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;font:inherit;font-weight:900;cursor:pointer}.error{background:#fee2e2;color:#991b1b;border-radius:11px;padding:11px;margin-bottom:15px}.foot{display:flex;justify-content:space-between;gap:12px;margin-top:18px;color:#64748b;font-size:13px}.foot a{color:#2563eb;text-decoration:none}
    </style>


</head>
<body>
    <form class="box" method="post">
        <div class="brand">IXR CLOUD</div>
        <h1 style="margin-bottom:22px">线路服务中心</h1>
        <?php if ($databaseError !== ''): ?><div class="error">系统暂时不可用：<?=up_h($databaseError)?></div><?php endif; ?>
        <?php if ($loginError !== ''): ?><div class="error"><?=up_h($loginError)?></div><?php endif; ?>
        <input type="hidden" name="login_action" value="1">
        <input type="hidden" name="csrf" value="<?=up_h($csrf)?>">
        <div class="field"><label>用户名</label><input name="username" required autocomplete="username" autofocus></div>
        <div class="field"><label>密码</label><input name="password" type="password" required autocomplete="current-password"></div>
        <button class="btn" type="submit" <?=$databaseError !== '' ? 'disabled' : ''?>>登录</button>
        <div class="foot" style="justify-content:flex-end"><a href="/admin.php">管理后台</a></div>
    </form>
</body>
</html>
<?php
exit;
endif;

$used = (int)$user['traffic_used_bytes'];
$limit = $user['traffic_limit_bytes'] === null ? null : (int)$user['traffic_limit_bytes'];
$remaining = $limit === null ? null : max(0, $limit - $used);
$percent = $limit === null || $limit <= 0 ? 0 : min(100, round($used * 100 / $limit, 2));
$status = (string)$user['status'];
$isActive = $status === 'active';
$statusMessage = match ($status) {
    'disabled' => '账户已被管理员停用，节点凭证暂不开放。',
    'expired' => '账户已经到期，请联系管理员续期。',
    'quota_exhausted' => '本周期流量额度已经用完，请联系管理员重置或增加额度。',
    default => '',
};
?>
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>线路服务中心</title>
    <style>
        :root{--bg:#f4f7fb;--card:#fff;--text:#172033;--muted:#64748b;--line:#e3e8f1;--blue:#2563eb;--green:#16a34a;--red:#dc2626;--shadow:0 16px 38px #1f293714}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",Arial,"Microsoft YaHei",sans-serif}.wrap{width:min(1180px,calc(100% - 28px));margin:24px auto 48px}.hero{position:relative;overflow:hidden;background:linear-gradient(135deg,#1d4ed8,#7c3aed);color:#fff;border-radius:26px;padding:28px;box-shadow:0 22px 48px #1f29372b}.hero:after{content:"";position:absolute;width:260px;height:260px;border-radius:50%;right:-80px;top:-120px;background:#ffffff18}.top{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;position:relative;z-index:1}.brand{font-size:13px;font-weight:900;letter-spacing:.15em;color:#dbeafe}.hero h1{margin:8px 0 4px}.hero p{margin:0;color:#e0e7ff}.logout{color:#fff;text-decoration:none;border:1px solid #ffffff55;border-radius:10px;padding:8px 11px;font-weight:800}.status{display:inline-flex;margin-top:18px;border-radius:999px;padding:7px 12px;background:#dcfce7;color:#166534;font-size:13px;font-weight:900}.status.disabled,.status.expired,.status.quota_exhausted{background:#fee2e2;color:#991b1b}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-top:18px}.card{background:var(--card);border:1px solid #edf1f7;border-radius:18px;padding:19px;box-shadow:var(--shadow)}.metric span{display:block;color:var(--muted);font-size:13px}.metric b{display:block;margin-top:6px;font-size:25px}.wide{grid-column:1/-1}.progress{height:11px;border-radius:999px;background:#e2e8f0;overflow:hidden;margin-top:12px}.progress i{display:block;height:100%;background:linear-gradient(90deg,#22c55e,#2563eb);width:var(--percent)}.notice{border-left:6px solid var(--green)}.notice.blocked{border-left-color:var(--red);background:#fff7f7}.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.section-head h2,.section-head h3{margin:0}.links{display:grid;gap:10px;margin-top:14px}.link-row{display:grid;grid-template-columns:90px minmax(0,1fr) auto;gap:8px;align-items:center}.link-row input,.node textarea{width:100%;min-width:0;border:1px solid var(--line);border-radius:11px;padding:10px;background:#f8fafc;font:inherit}.btn{border:0;border-radius:10px;padding:9px 12px;background:#eef2ff;color:#3730a3;font:inherit;font-weight:900;cursor:pointer}.nodes{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin-top:14px}.node{border:1px solid var(--line);border-radius:15px;padding:15px;background:#fbfdff}.node h3{margin:0}.node-meta{display:flex;flex-wrap:wrap;gap:8px 14px;color:var(--muted);font-size:13px;margin:8px 0 12px}.node textarea{min-height:90px;resize:vertical;word-break:break-all}.node-foot{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-top:9px}.hint{color:var(--muted);font-size:13px}.empty{text-align:center;color:var(--muted);padding:28px}@media(max-width:760px){.grid,.nodes{grid-template-columns:1fr}.link-row{grid-template-columns:1fr}.wrap{margin-top:12px}.top{align-items:center}.hero{padding:22px}}
    </style>
    <style>
        .account-card{margin:18px 0}.account-form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:14px}.account-form .field label{display:block;color:var(--muted);font-size:13px;font-weight:800;margin-bottom:6px}.account-form .field input{width:100%;border:1px solid var(--line);border-radius:11px;padding:10px 11px;background:#fff;font:inherit}.account-form .full{grid-column:1/-1}.account-form .save{background:var(--blue);color:#fff}.profile-message{border-radius:11px;padding:10px 12px;margin-top:13px;font-weight:800}.profile-message.success{background:#dcfce7;color:#166534}.profile-message.error{background:#fee2e2;color:#991b1b}@media(max-width:760px){.account-form{grid-template-columns:1fr}.account-form .full{grid-column:auto}}
    </style>

<!-- IXR_USER_TUTORIAL_STYLES_START -->
<style>
    .tutorial-card{margin-top:18px;overflow:hidden}.tutorial-card .section-head{align-items:flex-end}.tutorial-tabs{display:flex;gap:8px;margin:16px 0 0;border-bottom:1px solid var(--line);overflow-x:auto;padding-bottom:0}.tutorial-tab{border:0;background:transparent;color:var(--muted);font:inherit;font-weight:900;padding:11px 14px;border-radius:13px 13px 0 0;cursor:pointer;white-space:nowrap}.tutorial-tab.is-active{background:#eff6ff;color:#1d4ed8;box-shadow:inset 0 -2px 0 #2563eb}.tutorial-panel{display:none;margin-top:16px}.tutorial-panel.is-active{display:block}.tutorial-hero{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(280px,.9fr);gap:18px;align-items:center;padding:18px;border:1px solid #e6edfb;border-radius:20px;background:linear-gradient(135deg,#f8fbff,#eef2ff)}.tutorial-hero h3{margin:8px 0 8px;font-size:24px}.tutorial-hero p{margin:0;color:var(--muted);line-height:1.7}.tutorial-hero img{width:100%;max-height:220px;object-fit:contain}.tutorial-badge{display:inline-flex;align-items:center;border-radius:999px;background:#dbeafe;color:#1e40af;padding:6px 10px;font-size:12px;font-weight:900}.tutorial-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}.tutorial-actions .btn.primary{background:var(--blue);color:#fff;text-decoration:none}.tutorial-actions .btn.light{background:#fff;color:#1d4ed8;text-decoration:none;border:1px solid #dbeafe}.tutorial-steps{counter-reset:tutorial-step;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;list-style:none;padding:0;margin:16px 0 0}.tutorial-steps li{position:relative;border:1px solid var(--line);border-radius:16px;background:#fff;padding:15px 14px 14px 52px;min-height:96px}.tutorial-steps li:before{counter-increment:tutorial-step;content:counter(tutorial-step);position:absolute;left:14px;top:15px;width:26px;height:26px;border-radius:9px;background:#2563eb;color:#fff;display:grid;place-items:center;font-weight:900}.tutorial-steps b{display:block;margin-bottom:5px}.tutorial-steps span{display:block;color:var(--muted);font-size:13px;line-height:1.55}.tutorial-shots{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:16px}.tutorial-shots figure{margin:0;border:1px solid var(--line);border-radius:16px;background:#fbfdff;padding:10px}.tutorial-shots img{display:block;width:100%;height:155px;object-fit:cover;object-position:top;border-radius:12px;border:1px solid #edf1f7;background:#fff}.tutorial-shots figcaption{margin-top:8px;color:var(--muted);font-size:13px;text-align:center}.tutorial-faq{margin-top:16px;border:1px solid var(--line);border-radius:16px;background:#fbfdff;padding:12px 14px}.tutorial-faq summary{cursor:pointer;font-weight:900}.tutorial-faq ul{margin:10px 0 0;padding-left:20px;color:var(--muted);line-height:1.7}.tutorial-note{display:flex;gap:10px;align-items:flex-start;margin-top:14px;color:#475569;background:#f8fafc;border:1px dashed #cbd5e1;border-radius:14px;padding:12px}.tutorial-note b{color:#172033}@media(max-width:960px){.tutorial-hero,.tutorial-steps,.tutorial-shots{grid-template-columns:1fr}.tutorial-shots img{height:auto;max-height:260px;object-fit:contain}.tutorial-card .section-head{align-items:flex-start}}
.tutorial-hero img,.tutorial-shots img{cursor:zoom-in}.tutorial-lightbox{position:fixed;inset:0;z-index:9999;display:none;align-items:center;justify-content:center;padding:24px;background:#0f172add;backdrop-filter:blur(6px)}.tutorial-lightbox.is-open{display:flex}.tutorial-lightbox img{max-width:min(1120px,96vw);max-height:86vh;border-radius:18px;background:#fff;box-shadow:0 28px 80px #0008}.tutorial-lightbox-close{position:fixed;right:18px;top:18px;border:1px solid #ffffff40;border-radius:999px;background:#ffffff18;color:#fff;width:42px;height:42px;font-size:24px;line-height:1;cursor:pointer}.tutorial-lightbox-caption{position:fixed;left:24px;right:84px;bottom:18px;color:#e2e8f0;font-size:14px;text-align:center;pointer-events:none}@media(max-width:760px){.tutorial-lightbox{padding:12px}.tutorial-lightbox img{max-width:96vw;max-height:82vh}.tutorial-lightbox-close{right:12px;top:12px}}
</style>
<!-- IXR_USER_TUTORIAL_STYLES_END -->
</head>
<body>
<main class="wrap">
    <section class="hero">
        <div class="top">
            <div><div class="brand">IXR CLOUD</div><h1><?=up_h($user['display_name'])?></h1><div style="color:#e0e7ff">@<?=up_h($user['username'])?></div></div>
            <a class="logout" href="/?logout=1">退出登录</a>
        </div>
        <span class="status <?=up_h($status)?>"><?=up_h(ixr_status_label($status))?></span>
    </section>

    <section class="grid">
        <div class="card metric"><span>已用流量</span><b><?=up_h(ixr_format_bytes($used))?></b></div>
        <div class="card metric"><span>流量额度</span><b><?=up_h(ixr_format_bytes($limit))?></b></div>
        <div class="card metric"><span>剩余流量</span><b><?=up_h(ixr_format_bytes($remaining))?></b></div>
        <?php if ($limit !== null): ?><div class="card wide"><div class="section-head"><b>额度使用进度</b><span class="hint"><?=up_h($percent)?>%</span></div><div class="progress"><i style="--percent:<?=up_h($percent)?>%"></i></div></div><?php endif; ?>
        <div class="card metric"><span>到期时间</span><b><?=up_h($user['expires_at'] ?: '长期有效')?></b></div>
        <div class="card metric"><span>线路授权</span><b style="font-size:18px">IXR <?=up_h(count($ports))?> · IX <?=up_h(count($routes))?></b></div>
        <div class="card metric"><span>最后登录</span><b style="font-size:16px"><?=up_h($user['last_login_at'] ?: '首次登录')?></b></div>
        <?php if (!$isActive): ?><div class="card wide notice blocked"><b><?=up_h($statusMessage)?></b></div><?php endif; ?>
    </section>

    <section class="card account-card" id="account">
        <div class="section-head"><h2>账户设置</h2></div>
        <?php if ($profileSuccess !== ''): ?><div class="profile-message success"><?=up_h($profileSuccess)?></div><?php endif; ?>
        <?php if ($profileError !== ''): ?><div class="profile-message error"><?=up_h($profileError)?></div><?php endif; ?>
        <form method="post" class="account-form">
            <input type="hidden" name="profile_action" value="1">
            <input type="hidden" name="csrf" value="<?=up_h($csrf)?>">
            <div class="field"><label>显示名称</label><input name="display_name" required maxlength="100" value="<?=up_h($profileError !== '' ? ($_POST['display_name'] ?? $user['display_name']) : $user['display_name'])?>"></div>
            <div class="field"><label>用户名</label><input value="<?=up_h($user['username'])?>" readonly></div>
            <div class="field"><label>当前密码</label><input name="current_password" type="password" required autocomplete="current-password"></div>
            <div class="field"><label>新密码</label><input name="new_password" type="password" minlength="8" maxlength="200" autocomplete="new-password"></div>
            <div class="field"><label>确认新密码</label><input name="confirm_password" type="password" minlength="8" maxlength="200" autocomplete="new-password"></div>
            <div class="full"><button class="btn save" type="submit">保存账户设置</button></div>
        </form>
    </section>

    <?php if ($isActive): ?>
        <section class="card">
            <div class="section-head"><h2>订阅链接</h2><span class="hint">请妥善保管，链接等同于节点访问凭证。</span></div>
            <div class="links">
                <div class="link-row"><b>VMess</b><input id="subscription-vmess" readonly value="<?=up_h(ixr_subscription_url($user, 'v2ray'))?>"><button class="btn" type="button" onclick="copyValue('subscription-vmess',this)">复制</button></div>
                <div class="link-row"><b>Surge</b><input id="subscription-surge" readonly value="<?=up_h(ixr_subscription_url($user, 'surge'))?>"><button class="btn" type="button" onclick="copyValue('subscription-surge',this)">复制</button></div>
            </div>
        </section>


        <!-- IXR_USER_TUTORIALS_START -->
        <section class="card tutorial-card" id="client-tutorials">
            <div class="section-head">
                <h2>客户端使用教程</h2>
                <span class="hint">Windows 使用 v2rayN，安卓使用 v2rayNG。</span>
            </div>
            <div class="tutorial-tabs" role="tablist" aria-label="客户端使用教程">
                <button class="tutorial-tab is-active" type="button" role="tab" aria-selected="true" data-tutorial-tab="windows">Windows · v2rayN</button>
                <button class="tutorial-tab" type="button" role="tab" aria-selected="false" data-tutorial-tab="android">安卓 · v2rayNG</button>
            </div>

            <div class="tutorial-panel is-active" data-tutorial-panel="windows">
                <div class="tutorial-hero">
                    <div>
                        <span class="tutorial-badge">Windows 10 / 11</span>
                        <h3>v2rayN 基础使用</h3>
                        <p>适合电脑用户：下载客户端后，复制上方订阅链接，导入并更新订阅，选择节点后开启系统代理即可。</p>
                        <div class="tutorial-actions">
                            <a class="btn primary" href="https://github.com/2dust/v2rayN/releases/latest" target="_blank" rel="noopener">下载 v2rayN</a>
                            <button class="btn light" type="button" onclick="copyValue('subscription-vmess',this)">复制订阅链接</button>
                        </div>
                    </div>
                    <img src="/tutorials/v2rayn/assets/00-quick-start.svg" alt="v2rayN 四步上手">
                </div>
                <ol class="tutorial-steps">
                    <li><b>下载并解压</b><span>从 GitHub 官方发布页下载 Windows 64 位压缩包，完整解压后运行 v2rayN.exe。</span></li>
                    <li><b>添加订阅</b><span>打开“订阅分组设置”，新增订阅，把本页 VMess 订阅链接粘贴到 Url。</span></li>
                    <li><b>更新订阅</b><span>选择“更新全部订阅”，等待节点列表刷新出来；失败时先检查链接是否复制完整。</span></li>
                    <li><b>选择节点</b><span>右键节点并设为活动服务器；可以先测试真连接延迟，再选择体验更好的节点。</span></li>
                    <li><b>开启代理</b><span>在底部或托盘菜单选择“自动配置系统代理”，浏览器通常就能直接使用。</span></li>
                    <li><b>关闭代理</b><span>不用时先选择“清除系统代理”，避免退出客户端后 Windows 仍保留代理设置。</span></li>
                </ol>
                <div class="tutorial-shots">
                    <figure><img src="/tutorials/v2rayn/assets/02-subscription-settings.jpg" alt="v2rayN 添加订阅"><figcaption>添加订阅地址</figcaption></figure>
                    <figure><img src="/tutorials/v2rayn/assets/03-update-subscription.jpg" alt="v2rayN 更新订阅"><figcaption>更新全部订阅</figcaption></figure>
                    <figure><img src="/tutorials/v2rayn/assets/04-choose-node.jpg" alt="v2rayN 选择节点"><figcaption>选择活动服务器</figcaption></figure>
                </div>
                <details class="tutorial-faq">
                    <summary>Windows 常见问题</summary>
                    <ul>
                        <li>更新后没有节点：重新复制订阅链接，确认账户有效后再更新。</li>
                        <li>浏览器打不开：确认已设为活动服务器，并开启“自动配置系统代理”。</li>
                        <li>退出后断网：重新打开 v2rayN，选择“清除系统代理”。</li>
                    </ul>
                </details>
            </div>

            <div class="tutorial-panel" data-tutorial-panel="android">
                <div class="tutorial-hero">
                    <div>
                        <span class="tutorial-badge">Android 5.0+</span>
                        <h3>v2rayNG 安卓基础使用</h3>
                        <p>适合手机用户：安装 v2rayNG 后，导入订阅或节点链接，选择节点，点击右下角按钮并允许 VPN 连接。</p>
                        <div class="tutorial-actions">
                            <a class="btn primary" href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" rel="noopener">下载 APK</a>
                            <a class="btn light" href="https://play.google.com/store/apps/details?id=com.v2ray.ang" target="_blank" rel="noopener">Google Play</a>
                            <button class="btn light" type="button" onclick="copyValue('subscription-vmess',this)">复制订阅链接</button>
                        </div>
                    </div>
                    <img src="/tutorials/v2rayng/assets/00-quick-start.svg" alt="v2rayNG 四步上手">
                </div>
                <ol class="tutorial-steps">
                    <li><b>安装客户端</b><span>优先使用 Google Play；无法使用时，从 GitHub 官方发布页下载适合手机架构的 APK。</span></li>
                    <li><b>添加订阅</b><span>打开左上角菜单进入“订阅分组设置”，新增订阅并粘贴本页 VMess 订阅链接。</span></li>
                    <li><b>更新订阅</b><span>回到主界面，点击右上角菜单更新订阅，等待节点列表出现。</span></li>
                    <li><b>选择节点</b><span>点击一个节点完成选中；体验不好时可以直接切换到其他节点。</span></li>
                    <li><b>启动代理</b><span>点击右下角圆形按钮，首次启动时允许系统创建 VPN 连接。</span></li>
                    <li><b>后台保活</b><span>如果经常断开，把 v2rayNG 电池策略改为“不限制”，并允许后台运行。</span></li>
                </ol>
                <div class="tutorial-shots">
                    <figure><img src="/tutorials/v2rayng/assets/05-add-subscription.jpg" alt="v2rayNG 添加订阅"><figcaption>添加订阅地址</figcaption></figure>
                    <figure><img src="/tutorials/v2rayng/assets/06-update-subscription.jpg" alt="v2rayNG 更新订阅"><figcaption>更新订阅</figcaption></figure>
                    <figure><img src="/tutorials/v2rayng/assets/07-start-proxy.jpg" alt="v2rayNG 启动代理"><figcaption>启动并允许 VPN</figcaption></figure>
                </div>
                <details class="tutorial-faq">
                    <summary>安卓常见问题</summary>
                    <ul>
                        <li>显示已连接但打不开：切换节点，并确认没有同时开启其他 VPN。</li>
                        <li>订阅更新超时：切换 Wi-Fi / 移动网络后重试。</li>
                        <li>后台自动断开：关闭省电限制，把 v2rayNG 加入后台白名单。</li>
                    </ul>
                </details>
            </div>

            <div class="tutorial-note"><b>安全提醒：</b><span>订阅链接、节点链接、UUID 和二维码等同于账号凭证，请勿公开截图或转发给陌生人。</span></div>
        </section>

        <div class="tutorial-lightbox" id="tutorial-lightbox" aria-hidden="true">
            <button class="tutorial-lightbox-close" type="button" aria-label="关闭大图">×</button>
            <img alt="教程大图预览">
            <div class="tutorial-lightbox-caption"></div>
        </div>
        <!-- IXR_USER_TUTORIALS_END -->

        <section class="card">
            <div class="section-head"><h2>可用节点</h2></div>
            <?php if (!$nodes): ?>
                <div class="empty">管理员尚未为你分配 IXR 端口或 IX 线路。</div>
            <?php else: ?>
                <div class="nodes">
                    <?php foreach ($nodes as $node): $vmess = ixr_vmess_link($node); ?>
                        <article class="node">
                            <h3><?=up_h($node['label'])?></h3>
                            <div class="node-meta"><span><?=up_h($node['address'])?>:<?=up_h($node['port'])?></span><span>VMess / TCP</span><span><?=($node['node_type'] ?? '') === 'ix' ? 'IX 共享线路' : 'IXR 共享端口'?></span></div>
                            <textarea id="node-<?=up_h($node['node_key'])?>" readonly><?=up_h($vmess)?></textarea>
                            <div class="node-foot"><span class="hint">UUID：<?=up_h($node['uuid'])?></span><button class="btn" type="button" onclick="copyValue('node-<?=up_h($node['node_key'])?>',this)">复制节点</button></div>
                        </article>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </section>
    <?php endif; ?>
</main>
<script>
async function copyValue(id,button){const field=document.getElementById(id);if(!field)return;try{await navigator.clipboard.writeText(field.value);const old=button.textContent;button.textContent='已复制';setTimeout(()=>button.textContent=old,1400)}catch(error){field.select();document.execCommand('copy')}}

// IXR_USER_TUTORIALS_JS_START
function switchTutorial(target){document.querySelectorAll('[data-tutorial-tab]').forEach(tab=>{const active=tab.dataset.tutorialTab===target;tab.classList.toggle('is-active',active);tab.setAttribute('aria-selected',active?'true':'false')});document.querySelectorAll('[data-tutorial-panel]').forEach(panel=>panel.classList.toggle('is-active',panel.dataset.tutorialPanel===target))}
document.addEventListener('DOMContentLoaded',()=>{document.querySelectorAll('[data-tutorial-tab]').forEach(tab=>tab.addEventListener('click',()=>switchTutorial(tab.dataset.tutorialTab)));document.querySelectorAll('.tutorial-hero img,.tutorial-shots img').forEach(image=>image.addEventListener('click',()=>openTutorialImage(image)));const box=document.getElementById('tutorial-lightbox');if(box){box.addEventListener('click',event=>{if(event.target===box)closeTutorialImage()});const close=box.querySelector('.tutorial-lightbox-close');if(close)close.addEventListener('click',closeTutorialImage)}document.addEventListener('keydown',event=>{if(event.key==='Escape')closeTutorialImage()})})

function openTutorialImage(image){const box=document.getElementById('tutorial-lightbox');if(!box)return;const preview=box.querySelector('img');const caption=box.querySelector('.tutorial-lightbox-caption');preview.src=image.currentSrc||image.src;preview.alt=image.alt||'教程大图预览';caption.textContent=image.alt||'';box.classList.add('is-open');box.setAttribute('aria-hidden','false')}
function closeTutorialImage(){const box=document.getElementById('tutorial-lightbox');if(!box)return;box.classList.remove('is-open');box.setAttribute('aria-hidden','true');const preview=box.querySelector('img');if(preview)preview.removeAttribute('src')}
// IXR_USER_TUTORIALS_JS_END
</script>
</body>
</html>
