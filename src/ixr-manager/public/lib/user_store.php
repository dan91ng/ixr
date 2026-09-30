<?php
declare(strict_types=1);

date_default_timezone_set('Asia/Shanghai');

const IXR_USERS_DB = '/opt/ixr-manager/data/users.db';
const IXR_STATE_FILE = '/opt/ixr-manager/data/state.json';
const IXR_USAGE_FILE = '/opt/ixr-manager/data/usage.json';
const IXR_EXPORT_FILE = '/opt/ixr-manager/data/export.json';
const IXR_IX_ROUTES_FILE = '/opt/ixr-manager/data/ix_routes.json';
const IXR_OUTBOUNDS_FILE = '/opt/ixr-manager/data/outbounds.json';
const IXR_IX_LEGACY_FILE = '/opt/ixr-manager/data/ix_legacy.json';
const IXR_IX_ADDRESS = 'public.cloudc.dev';
const IXR_IX_PORT = 10183;
const IXR_MANAGED_EMAIL_SUFFIX = '@ixr.local';
const IXR_ADMIN_PASSWORD_FILE = '/opt/ixr-manager/data/admin_password_hash';

function ixr_env_path(string $name, string $default): string
{
    $value = getenv($name);
    return is_string($value) && $value !== '' ? $value : $default;
}

function ixr_user_database_path(): string
{
    return ixr_env_path('IXR_USERS_DB', IXR_USERS_DB);
}

function ixr_user_db(): PDO
{
    static $database = null;
    if ($database instanceof PDO) {
        return $database;
    }
    if (!extension_loaded('pdo_sqlite')) {
        throw new RuntimeException('PDO SQLite 扩展未启用');
    }
    $path = ixr_user_database_path();
    if (!is_file($path)) {
        throw new RuntimeException('IXR 用户数据库尚未初始化');
    }
    $database = new PDO('sqlite:' . $path, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $database->exec('PRAGMA foreign_keys = ON');
    $database->exec('PRAGMA busy_timeout = 10000');
    return $database;
}

function ixr_read_json(string $path, array $default = []): array
{
    if (!is_file($path)) {
        return $default;
    }
    $decoded = json_decode((string)file_get_contents($path), true);
    return is_array($decoded) ? $decoded : $default;
}

function ixr_string_list(mixed $value): array
{
    if (is_string($value)) {
        $value = trim($value);
        return $value === '' ? [] : [$value];
    }
    if (!is_array($value)) {
        return [];
    }
    $items = [];
    foreach ($value as $item) {
        $item = trim((string)$item);
        if ($item !== '') {
            $items[] = $item;
        }
    }
    return $items;
}

function ixr_is_managed_ix_email(string $email): bool
{
    return str_ends_with(strtolower(trim($email)), IXR_MANAGED_EMAIL_SUFFIX);
}

function ixr_now(): string
{
    return date('Y-m-d H:i:s');
}

function ixr_admin_password_file(): string
{
    return ixr_env_path('IXR_ADMIN_PASSWORD_FILE', IXR_ADMIN_PASSWORD_FILE);
}

function ixr_admin_password_hash_value(): ?string
{
    $path = ixr_admin_password_file();
    if (!is_file($path)) {
        return null;
    }
    $hash = trim((string)file_get_contents($path));
    $info = password_get_info($hash);
    if ($hash === '' || (string)($info['algoName'] ?? 'unknown') === 'unknown') {
        throw new RuntimeException('后台密码文件无效');
    }
    return $hash;
}

function ixr_verify_admin_password(string $password, string $fallbackPassword): bool
{
    $hash = ixr_admin_password_hash_value();
    return $hash === null ? hash_equals($fallbackPassword, $password) : password_verify($password, $hash);
}

function ixr_admin_password_version(string $fallbackPassword): string
{
    $hash = ixr_admin_password_hash_value();
    return hash('sha256', $hash === null ? 'fallback:' . $fallbackPassword : 'hash:' . $hash);
}

function ixr_mark_admin_session(string $fallbackPassword): void
{
    $_SESSION['ixr_login'] = true;
    $_SESSION['ixr_admin_password_version'] = ixr_admin_password_version($fallbackPassword);
}

function ixr_admin_session_valid(string $fallbackPassword): bool
{
    if (empty($_SESSION['ixr_login'])) {
        return false;
    }
    $currentVersion = ixr_admin_password_version($fallbackPassword);
    $sessionVersion = (string)($_SESSION['ixr_admin_password_version'] ?? '');
    if ($sessionVersion === '') {
        $_SESSION['ixr_admin_password_version'] = $currentVersion;
        return true;
    }
    return hash_equals($currentVersion, $sessionVersion);
}

function ixr_user_password_version(array $user): string
{
    return hash('sha256', 'user:' . (string)($user['password_hash'] ?? ''));
}

function ixr_mark_user_session(array $user): void
{
    $_SESSION['ixr_user_id'] = (int)$user['id'];
    $_SESSION['ixr_user_password_version'] = ixr_user_password_version($user);
}

function ixr_user_session_valid(array $user): bool
{
    $currentVersion = ixr_user_password_version($user);
    $sessionVersion = (string)($_SESSION['ixr_user_password_version'] ?? '');
    if ($sessionVersion === '') {
        $_SESSION['ixr_user_password_version'] = $currentVersion;
        return true;
    }
    return hash_equals($currentVersion, $sessionVersion);
}

function ixr_change_admin_password(string $currentPassword, string $newPassword, string $confirmPassword, string $fallbackPassword): void
{
    if (!ixr_verify_admin_password($currentPassword, $fallbackPassword)) {
        throw new InvalidArgumentException('当前密码不正确');
    }
    if ($newPassword !== $confirmPassword) {
        throw new InvalidArgumentException('两次输入的新密码不一致');
    }
    if (strlen($newPassword) < 8) {
        throw new InvalidArgumentException('新密码至少需要 8 位');
    }
    if (strlen($newPassword) > 200) {
        throw new InvalidArgumentException('新密码不能超过 200 位');
    }
    if (hash_equals($currentPassword, $newPassword)) {
        throw new InvalidArgumentException('新密码不能与当前密码相同');
    }
    $hash = password_hash($newPassword, PASSWORD_DEFAULT);
    if (!is_string($hash) || $hash === '') {
        throw new RuntimeException('新密码生成失败');
    }
    $path = ixr_admin_password_file();
    $directory = dirname($path);
    if (!is_dir($directory) || !is_writable($directory)) {
        throw new RuntimeException('后台密码目录不可写');
    }
    $temporary = tempnam($directory, '.ixr-admin-password-');
    if ($temporary === false) {
        throw new RuntimeException('无法创建后台密码临时文件');
    }
    try {
        if (file_put_contents($temporary, $hash . "\n", LOCK_EX) === false) {
            throw new RuntimeException('后台密码写入失败');
        }
        @chmod($temporary, 0600);
        if (!rename($temporary, $path)) {
            throw new RuntimeException('后台密码替换失败');
        }
        @chmod($path, 0600);
    } finally {
        if (is_file($temporary)) {
            @unlink($temporary);
        }
    }
}

function ixr_parse_expiry(string $value): ?string
{
    $value = trim($value);
    if ($value === '') {
        return null;
    }
    $timestamp = strtotime($value);
    if ($timestamp === false) {
        throw new InvalidArgumentException('到期时间格式无效');
    }
    return date('Y-m-d H:i:s', $timestamp);
}

function ixr_expiry_input(?string $value): string
{
    if ($value === null || $value === '') {
        return '';
    }
    $timestamp = strtotime($value);
    return $timestamp === false ? '' : date('Y-m-d\TH:i', $timestamp);
}

function ixr_limit_from_gb(string $value): ?int
{
    $value = trim($value);
    if ($value === '') {
        return null;
    }
    if (!is_numeric($value) || (float)$value <= 0) {
        throw new InvalidArgumentException('流量额度必须是大于 0 的 GB 数值');
    }
    return (int)round((float)$value * 1024 * 1024 * 1024);
}

function ixr_limit_to_gb(?int $bytes): string
{
    return $bytes === null ? '' : rtrim(rtrim(number_format($bytes / 1073741824, 2, '.', ''), '0'), '.');
}

function ixr_format_bytes(?int $bytes): string
{
    if ($bytes === null) {
        return '不限额';
    }
    $value = max(0, $bytes);
    $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    $index = 0;
    while ($value >= 1024 && $index < count($units) - 1) {
        $value /= 1024;
        $index++;
    }
    return number_format((float)$value, $index === 0 || $value >= 100 ? 0 : 2) . ' ' . $units[$index];
}

function ixr_effective_status(array $user, int $usedBytes): string
{
    if ((int)($user['enabled'] ?? 0) !== 1) {
        return 'disabled';
    }
    $expiresAt = trim((string)($user['expires_at'] ?? ''));
    if ($expiresAt !== '') {
        $expires = strtotime($expiresAt);
        if ($expires !== false && $expires <= time()) {
            return 'expired';
        }
    }
    $limit = $user['traffic_limit_bytes'] === null ? null : (int)$user['traffic_limit_bytes'];
    if ($limit !== null && $usedBytes >= $limit) {
        return 'quota_exhausted';
    }
    return 'active';
}

function ixr_status_label(string $status): string
{
    return match ($status) {
        'active' => '正常',
        'disabled' => '已停用',
        'quota_exhausted' => '额度耗尽',
        'expired' => '已到期',
        default => $status,
    };
}

function ixr_state_catalog(): array
{
    $state = ixr_read_json(ixr_env_path('IXR_STATE_FILE', IXR_STATE_FILE), ['ports' => []]);
    $export = ixr_read_json(ixr_env_path('IXR_EXPORT_FILE', IXR_EXPORT_FILE), []);
    $address = trim((string)($export['default_address'] ?? 'public.cloudc.dev')) ?: 'public.cloudc.dev';
    $aliases = is_array($export['aliases'] ?? null) ? $export['aliases'] : [];
    $catalog = [];
    foreach (($state['ports'] ?? []) as $portConfig) {
        if (!is_array($portConfig)) {
            continue;
        }
        $port = (int)($portConfig['port'] ?? 0);
        if ($port <= 0) {
            continue;
        }
        $catalog[$port] = [
            'port' => $port,
            'label' => trim((string)($aliases[(string)$port] ?? 'IXR-' . $port)) ?: 'IXR-' . $port,
            'address' => $address,
            'uuid' => (string)($portConfig['uuid'] ?? ''),
            'email' => (string)($portConfig['email'] ?? ''),
            'protocol' => (string)($portConfig['protocol'] ?? 'vmess'),
            'default' => (string)($portConfig['default'] ?? 'auto-fast'),
            'rules' => is_array($portConfig['rules'] ?? null) ? $portConfig['rules'] : [],
        ];
    }
    ksort($catalog);
    return $catalog;
}

function ixr_sync_port_labels(PDO $database, ?int $onlyPort = null): int
{
    $catalog = ixr_state_catalog();
    $updated = 0;
    $now = ixr_now();
    foreach ($catalog as $port => $config) {
        $port = (int)$port;
        if ($onlyPort !== null && $port !== $onlyPort) {
            continue;
        }
        $label = trim((string)($config['label'] ?? '')) ?: ('IXR-' . $port);
        $statement = $database->prepare('UPDATE user_ports SET label = ?, updated_at = ? WHERE port = ? AND label <> ?');
        $statement->execute([$label, $now, $port, $label]);
        $updated += $statement->rowCount();
    }
    return $updated;
}


function ixr_ix_route_catalog(): array
{
    $routeFile = ixr_read_json(ixr_env_path('IXR_IX_ROUTES_FILE', IXR_IX_ROUTES_FILE), []);
    $routeRows = is_array($routeFile['routes'] ?? null) ? $routeFile['routes'] : [];
    $fileCatalog = [];
    foreach ($routeRows as $route) {
        if (!is_array($route)) {
            continue;
        }
        $routeCode = trim((string)($route['route_code'] ?? ''));
        $outboundTag = trim((string)($route['outbound_tag'] ?? $routeCode));
        if ($routeCode === '' || $outboundTag === '') {
            continue;
        }
        $fileCatalog[$routeCode] = [
            'route_code' => $routeCode,
            'display_name' => trim((string)($route['display_name'] ?? $routeCode)) ?: $routeCode,
            'outbound_tag' => $outboundTag,
            'address' => trim((string)($route['address'] ?? IXR_IX_ADDRESS)) ?: IXR_IX_ADDRESS,
            'port' => max(1, (int)($route['port'] ?? IXR_IX_PORT)),
            'protocol' => trim((string)($route['protocol'] ?? 'vmess')) ?: 'vmess',
            'network' => trim((string)($route['network'] ?? 'tcp')) ?: 'tcp',
        ];
    }
    if ($fileCatalog) {
        return $fileCatalog;
    }

    $outboundRows = ixr_read_json(ixr_env_path('IXR_OUTBOUNDS_FILE', IXR_OUTBOUNDS_FILE), []);
    $legacy = ixr_read_json(ixr_env_path('IXR_IX_LEGACY_FILE', IXR_IX_LEGACY_FILE), []);
    $outboundByName = [];
    $outboundByTag = [];
    foreach ($outboundRows as $outbound) {
        if (!is_array($outbound)) {
            continue;
        }
        $name = trim((string)($outbound['name'] ?? ''));
        $tag = trim((string)($outbound['tag'] ?? ''));
        if ($name !== '' && $tag !== '') {
            $outboundByName[$name] = $outbound;
            $outboundByTag[$tag] = $outbound;
        }
    }

    $sharedPort = max(1, (int)($legacy['shared_port'] ?? IXR_IX_PORT));
    $sharedTag = trim((string)($legacy['shared_tag'] ?? 'mixed')) ?: 'mixed';
    $protocol = 'vmess';
    $network = 'tcp';
    foreach (($legacy['inbounds'] ?? []) as $inbound) {
        if (!is_array($inbound)) {
            continue;
        }
        if ((string)($inbound['tag'] ?? '') === $sharedTag || (int)($inbound['port'] ?? 0) === $sharedPort) {
            $protocol = trim((string)($inbound['protocol'] ?? 'vmess')) ?: 'vmess';
            $network = trim((string)($inbound['streamSettings']['network'] ?? 'tcp')) ?: 'tcp';
            break;
        }
    }

    $address = trim((string)(getenv('IXR_IX_ADDRESS') ?: IXR_IX_ADDRESS)) ?: IXR_IX_ADDRESS;
    $catalog = [];
    foreach (($legacy['legacy_routes'] ?? []) as $route) {
        if (!is_array($route)) {
            continue;
        }
        $routeCode = trim((string)($route['route_code'] ?? ''));
        $email = trim((string)($route['email'] ?? ''));
        if ($routeCode === '' || $email === '' || ixr_is_managed_ix_email($email) || isset($catalog[$routeCode])) {
            continue;
        }
        $outbound = $outboundByName[$routeCode] ?? $outboundByTag[$routeCode] ?? null;
        if (!is_array($outbound)) {
            continue;
        }
        $outboundTag = trim((string)($outbound['tag'] ?? ''));
        if ($outboundTag === '') {
            continue;
        }
        $catalog[$routeCode] = [
            'route_code' => $routeCode,
            'display_name' => $routeCode,
            'outbound_tag' => $outboundTag,
            'address' => $address,
            'port' => $sharedPort,
            'protocol' => $protocol,
            'network' => $network,
        ];
    }
    return $catalog;
}

function ixr_usage_snapshot(): array
{
    $usage = ixr_read_json(ixr_env_path('IXR_USAGE_FILE', IXR_USAGE_FILE), []);
    $ports = [];
    foreach (($usage['ports'] ?? []) as $item) {
        if (is_array($item) && (int)($item['port'] ?? 0) > 0) {
            $ports[(int)$item['port']] = max(0, (int)($item['total'] ?? 0));
        }
    }
    $users = [];
    $usageUsers = is_array($usage['managed_users'] ?? null) ? $usage['managed_users'] : ($usage['ix_users'] ?? []);
    foreach ($usageUsers as $item) {
        if (!is_array($item)) {
            continue;
        }
        $email = trim((string)($item['email'] ?? ''));
        if ($email !== '' && ixr_is_managed_ix_email($email)) {
            $users[$email] = [
                'uplink' => max(0, (int)($item['uplink'] ?? 0)),
                'downlink' => max(0, (int)($item['downlink'] ?? 0)),
            ];
        }
    }
    return [
        'ports' => $ports,
        'epoch' => max(0, (int)($usage['stats_since_at'] ?? $usage['xray_started_at'] ?? 0)),
        'users' => $users,
        'user_epoch' => max(0, (int)($usage['managed_user_started_at'] ?? $usage['ix_user_started_at'] ?? $usage['xray_started_at'] ?? $usage['v2ray_started_at'] ?? 0)),
        'routes' => $users,
        'route_epoch' => max(0, (int)($usage['managed_user_started_at'] ?? $usage['ix_user_started_at'] ?? $usage['xray_started_at'] ?? $usage['v2ray_started_at'] ?? 0)),
        'updated_at' => max(0, (int)($usage['updated_at'] ?? 0)),
    ];
}

function ixr_user_total_used(PDO $database, int $userId): int
{
    $statement = $database->prepare(
        'SELECT COALESCE((SELECT SUM(traffic_used_bytes) FROM user_ports WHERE user_id = ?), 0) + COALESCE((SELECT SUM(traffic_used_bytes) FROM user_routes WHERE user_id = ?), 0)'
    );
    $statement->execute([$userId, $userId]);
    return (int)$statement->fetchColumn();
}

function ixr_sync_user_status(PDO $database, int $userId): string
{
    $statement = $database->prepare('SELECT * FROM users WHERE id = ?');
    $statement->execute([$userId]);
    $user = $statement->fetch();
    if (!$user) {
        throw new RuntimeException('用户不存在');
    }
    $status = ixr_effective_status($user, ixr_user_total_used($database, $userId));
    if ($status !== $user['status']) {
        $update = $database->prepare('UPDATE users SET status = ?, updated_at = ? WHERE id = ?');
        $update->execute([$status, ixr_now(), $userId]);
    }
    return $status;
}

function ixr_audit(PDO $database, string $actor, string $action, string $targetType, ?int $targetId, array $details = [], bool $success = true): void
{
    $statement = $database->prepare(
        'INSERT INTO audit_logs(actor, action, target_type, target_id, details_json, success, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    );
    $statement->execute([
        $actor,
        $action,
        $targetType,
        $targetId,
        json_encode($details, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        $success ? 1 : 0,
        ixr_now(),
    ]);
}

function ixr_normalize_username(string $username): string
{
    $username = trim($username);
    if (!preg_match('/^[A-Za-z0-9_.-]{3,64}$/', $username)) {
        throw new InvalidArgumentException('用户名仅允许 3-64 位字母、数字、点、下划线和短横线');
    }
    return $username;
}

function ixr_normalize_display_name(string $displayName): string
{
    $displayName = trim($displayName);
    if ($displayName === '') {
        throw new InvalidArgumentException('显示名称不能为空');
    }
    if (preg_match('//u', $displayName) !== 1 || preg_match('/[\x00-\x1F\x7F]/u', $displayName)) {
        throw new InvalidArgumentException('显示名称包含无效字符');
    }
    $length = function_exists('mb_strlen') ? mb_strlen($displayName, 'UTF-8') : preg_match_all('/./us', $displayName);
    if ($length > 100) {
        throw new InvalidArgumentException('显示名称不能超过 100 个字符');
    }
    return $displayName;
}

function ixr_normalize_ports(array $ports): array
{
    $catalog = ixr_state_catalog();
    $normalized = [];
    foreach ($ports as $port) {
        $value = (int)$port;
        if (isset($catalog[$value])) {
            $normalized[$value] = $value;
        }
    }
    ksort($normalized);
    return array_values($normalized);
}

function ixr_normalize_routes(array $routes): array
{
    $catalog = ixr_ix_route_catalog();
    $requested = [];
    foreach ($routes as $routeCode) {
        $routeCode = trim((string)$routeCode);
        if ($routeCode !== '' && isset($catalog[$routeCode])) {
            $requested[$routeCode] = true;
        }
    }
    $normalized = [];
    foreach ($catalog as $routeCode => $_route) {
        if (isset($requested[$routeCode])) {
            $normalized[] = $routeCode;
        }
    }
    return $normalized;
}

function ixr_uuid_v4(): string
{
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
    $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
    $hex = bin2hex($bytes);
    return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20, 12);
}

function ixr_route_email(int $userId, string $routeCode): string
{
    $slug = strtolower((string)preg_replace('/[^A-Za-z0-9]+/', '-', $routeCode));
    $slug = trim($slug, '-');
    if ($slug === '') {
        $slug = 'route';
    }
    $slug = substr($slug, 0, 32);
    return sprintf('u%06d.%s.%s%s', $userId, $slug, bin2hex(random_bytes(4)), IXR_MANAGED_EMAIL_SUFFIX);
}

function ixr_port_email(int $userId, int $port): string
{
    return sprintf('u%06d.p%d.%s%s', $userId, $port, bin2hex(random_bytes(4)), IXR_MANAGED_EMAIL_SUFFIX);
}

function ixr_assign_ports(PDO $database, int $userId, array $ports): void
{
    $ports = ixr_normalize_ports($ports);
    $catalog = ixr_state_catalog();
    $snapshot = ixr_usage_snapshot();
    $now = ixr_now();
    $selected = array_fill_keys($ports, true);

    $currentStatement = $database->prepare('SELECT id, port FROM user_ports WHERE user_id = ? AND active = 1');
    $currentStatement->execute([$userId]);
    foreach ($currentStatement->fetchAll() as $assignment) {
        $port = (int)$assignment['port'];
        if (!isset($selected[$port])) {
            $update = $database->prepare('UPDATE user_ports SET active = 0, unassigned_at = ?, updated_at = ? WHERE id = ?');
            $update->execute([$now, $now, (int)$assignment['id']]);
        }
    }

    foreach ($ports as $port) {
        $activeStatement = $database->prepare('SELECT id FROM user_ports WHERE user_id = ? AND port = ? AND active = 1');
        $activeStatement->execute([$userId, $port]);
        $active = $activeStatement->fetch();
        $label = $catalog[$port]['label'] ?? ('IXR-' . $port);
        if ($active) {
            $update = $database->prepare('UPDATE user_ports SET label = ?, updated_at = ? WHERE id = ?');
            $update->execute([$label, $now, (int)$active['id']]);
            continue;
        }
        $email = ixr_port_email($userId, $port);
        $counter = $snapshot['users'][$email] ?? ['uplink' => 0, 'downlink' => 0];
        $insert = $database->prepare(
            'INSERT INTO user_ports(user_id, port, label, uuid, xray_email, active, traffic_used_bytes, last_counter_bytes, last_uplink_bytes, last_downlink_bytes, last_counter_epoch, assigned_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?, ?, ?, ?, ?)'
        );
        $insert->execute([
            $userId,
            $port,
            $label,
            ixr_uuid_v4(),
            $email,
            (int)($counter['uplink'] ?? 0) + (int)($counter['downlink'] ?? 0),
            (int)($counter['uplink'] ?? 0),
            (int)($counter['downlink'] ?? 0),
            (int)$snapshot['user_epoch'],
            $now,
            $now,
        ]);
    }
}

function ixr_assign_routes(PDO $database, int $userId, array $routes): void
{
    $catalog = ixr_ix_route_catalog();
    if (!$catalog) {
        if ($routes) {
            throw new RuntimeException('IX 线路目录暂时不可用');
        }
        return;
    }

    $routes = ixr_normalize_routes($routes);
    $snapshot = ixr_usage_snapshot();
    $now = ixr_now();
    $selected = array_fill_keys($routes, true);

    $currentStatement = $database->prepare('SELECT id, route_code FROM user_routes WHERE user_id = ? AND active = 1');
    $currentStatement->execute([$userId]);
    foreach ($currentStatement->fetchAll() as $assignment) {
        $routeCode = (string)$assignment['route_code'];
        if (!isset($selected[$routeCode])) {
            $update = $database->prepare('UPDATE user_routes SET active = 0, unassigned_at = ?, updated_at = ? WHERE id = ?');
            $update->execute([$now, $now, (int)$assignment['id']]);
        }
    }

    foreach ($routes as $routeCode) {
        $route = $catalog[$routeCode];
        $activeStatement = $database->prepare('SELECT id, xray_email FROM user_routes WHERE user_id = ? AND route_code = ? AND active = 1');
        $activeStatement->execute([$userId, $routeCode]);
        $active = $activeStatement->fetch();
        if ($active) {
            $update = $database->prepare('UPDATE user_routes SET display_name = ?, outbound_tag = ?, updated_at = ? WHERE id = ?');
            $update->execute([(string)$route['display_name'], (string)$route['outbound_tag'], $now, (int)$active['id']]);
            continue;
        }

        $email = ixr_route_email($userId, $routeCode);
        $counter = $snapshot['routes'][$email] ?? ['uplink' => 0, 'downlink' => 0];
        $insert = $database->prepare(
            'INSERT INTO user_routes(user_id, route_code, display_name, outbound_tag, uuid, xray_email, active, traffic_used_bytes, last_uplink_bytes, last_downlink_bytes, last_counter_epoch, assigned_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?, ?, ?)'
        );
        $insert->execute([
            $userId,
            $routeCode,
            (string)$route['display_name'],
            (string)$route['outbound_tag'],
            ixr_uuid_v4(),
            $email,
            (int)($counter['uplink'] ?? 0),
            (int)($counter['downlink'] ?? 0),
            (int)$snapshot['route_epoch'],
            $now,
            $now,
        ]);
    }
}

function ixr_create_user(PDO $database, array $input, string $actor = 'admin'): int
{
    $username = ixr_normalize_username((string)($input['username'] ?? ''));
    $displayName = trim((string)($input['display_name'] ?? '')) ?: $username;
    $password = (string)($input['password'] ?? '');
    if (strlen($password) < 8) {
        throw new InvalidArgumentException('用户密码至少需要 8 位');
    }
    $now = ixr_now();
    $database->beginTransaction();
    try {
        $statement = $database->prepare(
            'INSERT INTO users(username, display_name, password_hash, subscription_token, enabled, status, traffic_limit_bytes, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        );
        $statement->execute([
            $username,
            $displayName,
            password_hash($password, PASSWORD_DEFAULT),
            bin2hex(random_bytes(32)),
            !empty($input['enabled']) ? 1 : 0,
            !empty($input['enabled']) ? 'active' : 'disabled',
            ixr_limit_from_gb((string)($input['traffic_limit_gb'] ?? '')),
            ixr_parse_expiry((string)($input['expires_at'] ?? '')),
            $now,
            $now,
        ]);
        $userId = (int)$database->lastInsertId();
        ixr_assign_ports($database, $userId, is_array($input['ports'] ?? null) ? $input['ports'] : []);
        ixr_assign_routes($database, $userId, is_array($input['routes'] ?? null) ? $input['routes'] : []);
        $status = ixr_sync_user_status($database, $userId);
        ixr_audit($database, $actor, 'user_created', 'user', $userId, [
            'username' => $username,
            'status' => $status,
            'ports' => ixr_normalize_ports($input['ports'] ?? []),
            'routes' => ixr_normalize_routes($input['routes'] ?? []),
        ]);
        $database->commit();
        return $userId;
    } catch (Throwable $error) {
        if ($database->inTransaction()) {
            $database->rollBack();
        }
        throw $error;
    }
}

function ixr_update_user(PDO $database, int $userId, array $input, string $actor = 'admin'): void
{
    $statement = $database->prepare('SELECT * FROM users WHERE id = ?');
    $statement->execute([$userId]);
    $existing = $statement->fetch();
    if (!$existing) {
        throw new RuntimeException('用户不存在');
    }
    $displayName = trim((string)($input['display_name'] ?? '')) ?: (string)$existing['username'];
    $password = (string)($input['password'] ?? '');
    if ($password !== '' && strlen($password) < 8) {
        throw new InvalidArgumentException('新密码至少需要 8 位');
    }
    $database->beginTransaction();
    try {
        if ($password !== '') {
            $update = $database->prepare('UPDATE users SET display_name = ?, password_hash = ?, enabled = ?, traffic_limit_bytes = ?, expires_at = ?, updated_at = ? WHERE id = ?');
            $update->execute([$displayName, password_hash($password, PASSWORD_DEFAULT), !empty($input['enabled']) ? 1 : 0, ixr_limit_from_gb((string)($input['traffic_limit_gb'] ?? '')), ixr_parse_expiry((string)($input['expires_at'] ?? '')), ixr_now(), $userId]);
        } else {
            $update = $database->prepare('UPDATE users SET display_name = ?, enabled = ?, traffic_limit_bytes = ?, expires_at = ?, updated_at = ? WHERE id = ?');
            $update->execute([$displayName, !empty($input['enabled']) ? 1 : 0, ixr_limit_from_gb((string)($input['traffic_limit_gb'] ?? '')), ixr_parse_expiry((string)($input['expires_at'] ?? '')), ixr_now(), $userId]);
        }
        ixr_assign_ports($database, $userId, is_array($input['ports'] ?? null) ? $input['ports'] : []);
        ixr_assign_routes($database, $userId, is_array($input['routes'] ?? null) ? $input['routes'] : []);
        $status = ixr_sync_user_status($database, $userId);
        ixr_audit($database, $actor, 'user_updated', 'user', $userId, [
            'status' => $status,
            'ports' => ixr_normalize_ports($input['ports'] ?? []),
            'routes' => ixr_normalize_routes($input['routes'] ?? []),
            'password_changed' => $password !== '',
        ]);
        $database->commit();
    } catch (Throwable $error) {
        if ($database->inTransaction()) {
            $database->rollBack();
        }
        throw $error;
    }
}

function ixr_reset_user_usage(PDO $database, int $userId, string $actor = 'admin'): void
{
    $snapshot = ixr_usage_snapshot();
    $database->beginTransaction();
    try {
        $statement = $database->prepare('SELECT id, xray_email, active FROM user_ports WHERE user_id = ?');
        $statement->execute([$userId]);
        foreach ($statement->fetchAll() as $assignment) {
            $email = (string)$assignment['xray_email'];
            $counter = (int)$assignment['active'] === 1 ? ($snapshot['users'][$email] ?? ['uplink' => 0, 'downlink' => 0]) : ['uplink' => 0, 'downlink' => 0];
            $uplink = (int)($counter['uplink'] ?? 0);
            $downlink = (int)($counter['downlink'] ?? 0);
            $epoch = (int)$assignment['active'] === 1 ? (int)$snapshot['user_epoch'] : 0;
            $update = $database->prepare('UPDATE user_ports SET traffic_used_bytes = 0, last_counter_bytes = ?, last_uplink_bytes = ?, last_downlink_bytes = ?, last_counter_epoch = ?, updated_at = ? WHERE id = ?');
            $update->execute([$uplink + $downlink, $uplink, $downlink, $epoch, ixr_now(), (int)$assignment['id']]);
        }
        $routeStatement = $database->prepare('SELECT id, xray_email, active FROM user_routes WHERE user_id = ?');
        $routeStatement->execute([$userId]);
        foreach ($routeStatement->fetchAll() as $assignment) {
            $email = (string)$assignment['xray_email'];
            $counter = (int)$assignment['active'] === 1 ? ($snapshot['routes'][$email] ?? ['uplink' => 0, 'downlink' => 0]) : ['uplink' => 0, 'downlink' => 0];
            $epoch = (int)$assignment['active'] === 1 ? (int)$snapshot['route_epoch'] : 0;
            $update = $database->prepare('UPDATE user_routes SET traffic_used_bytes = 0, last_uplink_bytes = ?, last_downlink_bytes = ?, last_counter_epoch = ?, updated_at = ? WHERE id = ?');
            $update->execute([
                (int)($counter['uplink'] ?? 0),
                (int)($counter['downlink'] ?? 0),
                $epoch,
                ixr_now(),
                (int)$assignment['id'],
            ]);
        }
        $status = ixr_sync_user_status($database, $userId);
        ixr_audit($database, $actor, 'usage_reset', 'user', $userId, ['status' => $status]);
        $database->commit();
    } catch (Throwable $error) {
        if ($database->inTransaction()) {
            $database->rollBack();
        }
        throw $error;
    }
}

function ixr_rotate_subscription_token(PDO $database, int $userId, string $actor = 'admin'): string
{
    $token = bin2hex(random_bytes(32));
    $statement = $database->prepare('UPDATE users SET subscription_token = ?, updated_at = ? WHERE id = ?');
    $statement->execute([$token, ixr_now(), $userId]);
    if ($statement->rowCount() !== 1) {
        throw new RuntimeException('用户不存在');
    }
    ixr_audit($database, $actor, 'subscription_token_rotated', 'user', $userId);
    return $token;
}

function ixr_delete_user(PDO $database, int $userId, string $actor = 'admin'): void
{
    $count = $database->prepare(
        'SELECT (SELECT COUNT(*) FROM user_ports WHERE user_id = ? AND active = 1) + (SELECT COUNT(*) FROM user_routes WHERE user_id = ? AND active = 1)'
    );
    $count->execute([$userId, $userId]);
    if ((int)$count->fetchColumn() > 0) {
        throw new RuntimeException('删除用户前请先解除全部 IXR 端口和 IX 线路授权');
    }
    $statement = $database->prepare('SELECT username FROM users WHERE id = ?');
    $statement->execute([$userId]);
    $username = $statement->fetchColumn();
    if ($username === false) {
        throw new RuntimeException('用户不存在');
    }
    $delete = $database->prepare('DELETE FROM users WHERE id = ?');
    $delete->execute([$userId]);
    ixr_audit($database, $actor, 'user_deleted', 'user', $userId, ['username' => $username]);
}

function ixr_user_by_id(PDO $database, int $userId): ?array
{
    $statement = $database->prepare('SELECT * FROM users WHERE id = ?');
    $statement->execute([$userId]);
    $user = $statement->fetch();
    if (!$user) {
        return null;
    }
    $user['traffic_used_bytes'] = ixr_user_total_used($database, $userId);
    $user['status'] = ixr_effective_status($user, (int)$user['traffic_used_bytes']);
    return $user;
}

function ixr_user_by_token(PDO $database, string $token): ?array
{
    $statement = $database->prepare('SELECT id FROM users WHERE subscription_token = ?');
    $statement->execute([$token]);
    $userId = $statement->fetchColumn();
    return $userId === false ? null : ixr_user_by_id($database, (int)$userId);
}

function ixr_authenticate_user(PDO $database, string $username, string $password): ?array
{
    $statement = $database->prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE');
    $statement->execute([trim($username)]);
    $user = $statement->fetch();
    if (!$user || !password_verify($password, (string)$user['password_hash'])) {
        return null;
    }
    $database->prepare('UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?')->execute([ixr_now(), ixr_now(), (int)$user['id']]);
    ixr_audit($database, (string)$user['username'], 'user_login', 'user', (int)$user['id']);
    return ixr_user_by_id($database, (int)$user['id']);
}

function ixr_update_own_profile(PDO $database, int $userId, array $input): array
{
    $statement = $database->prepare('SELECT id, username, display_name, password_hash FROM users WHERE id = ?');
    $statement->execute([$userId]);
    $user = $statement->fetch();
    if (!$user) {
        throw new RuntimeException('用户不存在');
    }
    $currentPassword = (string)($input['current_password'] ?? '');
    if ($currentPassword === '' || !password_verify($currentPassword, (string)$user['password_hash'])) {
        throw new InvalidArgumentException('当前密码不正确');
    }
    $displayName = ixr_normalize_display_name((string)($input['display_name'] ?? ''));
    $newPassword = (string)($input['new_password'] ?? '');
    $confirmPassword = (string)($input['confirm_password'] ?? '');
    if ($newPassword === '' && $confirmPassword !== '') {
        throw new InvalidArgumentException('请填写新密码');
    }
    if ($newPassword !== '') {
        if ($newPassword !== $confirmPassword) {
            throw new InvalidArgumentException('两次输入的新密码不一致');
        }
        if (strlen($newPassword) < 8) {
            throw new InvalidArgumentException('新密码至少需要 8 位');
        }
        if (strlen($newPassword) > 200) {
            throw new InvalidArgumentException('新密码不能超过 200 位');
        }
        if (hash_equals($currentPassword, $newPassword)) {
            throw new InvalidArgumentException('新密码不能与当前密码相同');
        }
    }
    $displayNameChanged = $displayName !== (string)$user['display_name'];
    $passwordChanged = $newPassword !== '';
    if (!$displayNameChanged && !$passwordChanged) {
        throw new InvalidArgumentException('没有需要保存的修改');
    }
    $database->beginTransaction();
    try {
        if ($passwordChanged) {
            $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);
            if (!is_string($passwordHash) || $passwordHash === '') {
                throw new RuntimeException('新密码生成失败');
            }
            $update = $database->prepare('UPDATE users SET display_name = ?, password_hash = ?, updated_at = ? WHERE id = ?');
            $update->execute([$displayName, $passwordHash, ixr_now(), $userId]);
        } else {
            $update = $database->prepare('UPDATE users SET display_name = ?, updated_at = ? WHERE id = ?');
            $update->execute([$displayName, ixr_now(), $userId]);
        }
        ixr_audit($database, (string)$user['username'], 'profile_updated', 'user', $userId, [
            'display_name_changed' => $displayNameChanged,
            'password_changed' => $passwordChanged,
        ]);
        $database->commit();
    } catch (Throwable $error) {
        if ($database->inTransaction()) {
            $database->rollBack();
        }
        throw $error;
    }
    return [
        'display_name_changed' => $displayNameChanged,
        'password_changed' => $passwordChanged,
    ];
}

function ixr_user_ports(PDO $database, int $userId): array
{
    $catalog = ixr_state_catalog();
    $statement = $database->prepare('SELECT * FROM user_ports WHERE user_id = ? AND active = 1 ORDER BY port');
    $statement->execute([$userId]);
    $ports = [];
    foreach ($statement->fetchAll() as $assignment) {
        $port = (int)$assignment['port'];
        $catalogLabel = (string)($catalog[$port]['label'] ?? $assignment['label'] ?? ('IXR-' . $port));
        $portConfig = $catalog[$port] ?? ['port' => $port, 'missing' => true];
        $portConfig = array_merge($portConfig, $assignment);
        $portConfig['label'] = $catalogLabel;
        $portConfig['uuid'] = (string)$assignment['uuid'];
        $portConfig['email'] = (string)$assignment['xray_email'];
        $ports[] = $portConfig;
    }
    return $ports;
}

function ixr_user_routes(PDO $database, int $userId): array
{
    $catalog = ixr_ix_route_catalog();
    $statement = $database->prepare('SELECT * FROM user_routes WHERE user_id = ? AND active = 1 ORDER BY id');
    $statement->execute([$userId]);
    $routes = [];
    foreach ($statement->fetchAll() as $assignment) {
        $routeCode = (string)$assignment['route_code'];
        $route = $catalog[$routeCode] ?? [
            'route_code' => $routeCode,
            'display_name' => (string)$assignment['display_name'],
            'outbound_tag' => (string)$assignment['outbound_tag'],
            'address' => trim((string)(getenv('IXR_IX_ADDRESS') ?: IXR_IX_ADDRESS)) ?: IXR_IX_ADDRESS,
            'port' => max(1, (int)(getenv('IXR_IX_PORT') ?: IXR_IX_PORT)),
            'protocol' => 'vmess',
            'network' => 'tcp',
            'missing' => true,
        ];
        $route['id'] = (int)$assignment['id'];
        $route['user_id'] = (int)$assignment['user_id'];
        $route['route_code'] = $routeCode;
        $route['display_name'] = (string)$assignment['display_name'];
        $route['outbound_tag'] = (string)$assignment['outbound_tag'];
        $route['uuid'] = (string)$assignment['uuid'];
        $route['email'] = (string)$assignment['xray_email'];
        $route['traffic_used_bytes'] = (int)$assignment['traffic_used_bytes'];
        $route['label'] = 'IX | ' . $route['display_name'];
        $route['node_type'] = 'ix';
        $route['node_key'] = 'ix-' . (int)$assignment['id'];
        $routes[] = $route;
    }
    return $routes;
}

function ixr_user_nodes(PDO $database, int $userId): array
{
    $user = ixr_user_by_id($database, $userId);
    $username = trim((string)($user['username'] ?? ''));
    $labelPrefix = $username !== '' ? $username . ' | ' : '';
    $nodes = [];
    foreach (ixr_user_ports($database, $userId) as $port) {
        $port['label'] = $labelPrefix . 'IXR | ' . (string)$port['label'];
        $port['node_type'] = 'ixr';
        $port['node_key'] = 'ixr-' . (int)$port['port'];
        $nodes[] = $port;
    }
    foreach (ixr_user_routes($database, $userId) as $route) {
        $route['label'] = $labelPrefix . (string)$route['label'];
        $nodes[] = $route;
    }
    return $nodes;
}

function ixr_list_users(PDO $database): array
{
    $users = $database->query('SELECT * FROM users ORDER BY username COLLATE NOCASE')->fetchAll();
    foreach ($users as &$user) {
        $userId = (int)$user['id'];
        $user['traffic_used_bytes'] = ixr_user_total_used($database, $userId);
        $user['status'] = ixr_effective_status($user, (int)$user['traffic_used_bytes']);
        $user['ports'] = ixr_user_ports($database, $userId);
        $user['routes'] = ixr_user_routes($database, $userId);
    }
    unset($user);
    return $users;
}

function ixr_active_port_owners(PDO $database): array
{
    $rows = $database->query(
        'SELECT up.port, up.user_id, u.username FROM user_ports up JOIN users u ON u.id = up.user_id WHERE up.active = 1 ORDER BY up.port'
    )->fetchAll();
    $owners = [];
    foreach ($rows as $row) {
        $owners[(int)$row['port']][] = $row;
    }
    return $owners;
}

function ixr_active_port_assignment_count(PDO $database): int
{
    return (int)$database->query('SELECT COUNT(*) FROM user_ports WHERE active = 1')->fetchColumn();
}

function ixr_active_route_assignment_count(PDO $database): int
{
    return (int)$database->query('SELECT COUNT(*) FROM user_routes WHERE active = 1')->fetchColumn();
}

function ixr_schedule_apply(string $reason): void
{
    $reason = substr(trim($reason), 0, 200);
    shell_exec('/usr/local/bin/ixr-apply-async ' . escapeshellarg($reason ?: '用户配置变更') . ' >/dev/null 2>&1 &');
}

function ixr_schedule_runtime_sync(string $reason): void
{
    $reason = substr(trim($reason), 0, 200);
    shell_exec('/usr/local/bin/ixr-runtime-sync ' . escapeshellarg($reason ?: '用户运行状态变更') . ' >/dev/null 2>&1 &');
}

function ixr_csrf_token(): string
{
    if (empty($_SESSION['ixr_csrf'])) {
        $_SESSION['ixr_csrf'] = bin2hex(random_bytes(24));
    }
    return (string)$_SESSION['ixr_csrf'];
}

function ixr_verify_csrf(string $token): bool
{
    return isset($_SESSION['ixr_csrf']) && hash_equals((string)$_SESSION['ixr_csrf'], $token);
}

function ixr_vmess_link(array $port): string
{
    $payload = [
        'v' => '2',
        'ps' => (string)($port['label'] ?? ('IXR-' . $port['port'])),
        'add' => (string)($port['address'] ?? 'public.cloudc.dev'),
        'port' => (string)$port['port'],
        'id' => (string)($port['uuid'] ?? ''),
        'aid' => '0',
        'scy' => 'auto',
        'net' => 'tcp',
        'type' => 'none',
        'host' => '',
        'path' => '',
        'tls' => '',
    ];
    return 'vmess://' . base64_encode((string)json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
}

function ixr_surge_line(array $port): string
{
    $name = str_replace([',', '='], '-', (string)($port['label'] ?? ('IXR-' . $port['port'])));
    return sprintf('%s = vmess, %s, %d, username=%s, vmess-aead=true, tls=false', $name, $port['address'], $port['port'], $port['uuid']);
}

function ixr_subscription_url(array $user, string $format): string
{
    $base = trim((string)getenv('IXR_PUBLIC_BASE_URL'));
    if ($base === '') {
        $export = ixr_read_json(ixr_env_path('IXR_EXPORT_FILE', IXR_EXPORT_FILE), []);
        $host = trim((string)($export['default_address'] ?? ''));
        $base = $host !== '' ? $host : (string)($_SERVER['HTTP_HOST'] ?? '');
    }
    if ($base === '') {
        $base = 'public.example.com';
    }
    if (!preg_match('~^https?://~i', $base)) {
        $base = 'https://' . $base;
    }
    $base = rtrim($base, '/');
    return $base . '/subscription.php?token=' . rawurlencode((string)$user['subscription_token']) . '&format=' . rawurlencode($format);
}

