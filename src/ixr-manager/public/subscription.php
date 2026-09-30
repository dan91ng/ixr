<?php
declare(strict_types=1);

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');

require_once __DIR__ . '/lib/user_store.php';

function subscription_fail(int $status, string $message): never
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8');
    echo $message . "\n";
    exit;
}

$token = strtolower(trim((string)($_GET['token'] ?? '')));
if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    subscription_fail(404, '订阅不存在');
}

try {
    $database = ixr_user_db();
    $user = ixr_user_by_token($database, $token);
} catch (Throwable $error) {
    subscription_fail(503, '订阅服务暂时不可用');
}

if (!$user) {
    subscription_fail(404, '订阅不存在');
}
if ((string)$user['status'] !== 'active') {
    subscription_fail(403, '账户当前不可用：' . ixr_status_label((string)$user['status']));
}

$format = strtolower(trim((string)($_GET['format'] ?? 'v2ray')));
if ($format === 'base64') {
    $format = 'v2ray';
}
if (!in_array($format, ['v2ray', 'surge'], true)) {
    subscription_fail(400, '不支持的订阅格式');
}

$nodes = ixr_user_nodes($database, (int)$user['id']);
$used = max(0, (int)$user['traffic_used_bytes']);
$userInfo = ['upload=0', 'download=' . $used];
if ($user['traffic_limit_bytes'] !== null) {
    $userInfo[] = 'total=' . max(0, (int)$user['traffic_limit_bytes']);
}
if (!empty($user['expires_at'])) {
    $expires = strtotime((string)$user['expires_at']);
    if ($expires !== false) {
        $userInfo[] = 'expire=' . $expires;
    }
}

header('Content-Type: text/plain; charset=utf-8');
header('Subscription-Userinfo: ' . implode('; ', $userInfo));
header('Profile-Title: base64:' . base64_encode('IXR - ' . (string)$user['display_name']));
header('Content-Disposition: inline; filename="ixr-' . $format . '.txt"');

if ($format === 'surge') {
    $lines = [
        '#!MANAGED-CONFIG ' . ixr_subscription_url($user, 'surge') . ' interval=86400 strict=false',
        '',
        '[Proxy]',
    ];
    foreach ($nodes as $node) {
        if (!empty($node['uuid'])) {
            $lines[] = ixr_surge_line($node);
        }
    }
    echo implode("\n", $lines) . "\n";
    exit;
}

$links = [];
foreach ($nodes as $node) {
    if (!empty($node['uuid'])) {
        $links[] = ixr_vmess_link($node);
    }
}
echo base64_encode(implode("\n", $links));
exit;
