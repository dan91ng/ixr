<?php
declare(strict_types=1);

function ixr_admin_xray_call(string $action, array $input = []): array
{
    $command = ['sudo', '-n', '/usr/local/bin/ixr-admin-xray'];
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $process = proc_open($command, $descriptors, $pipes, null, ['PATH' => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin']);
    if (!is_resource($process)) {
        throw new RuntimeException('无法启动 IXR Xray 管理后端');
    }

    fwrite($pipes[0], json_encode(['action' => $action, 'input' => $input], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    $code = proc_close($process);

    $decoded = json_decode(trim((string)$stdout), true);
    if (!is_array($decoded)) {
        $message = trim((string)$stderr);
        throw new RuntimeException($message !== '' ? $message : 'IXR Xray 管理后端返回无效结果');
    }
    if ($code !== 0 && !isset($decoded['error'])) {
        $decoded['success'] = false;
        $decoded['error'] = 'IXR Xray 管理后端执行失败';
    }
    return $decoded;
}

function ixr_admin_xray_panel_data(): array
{
    $result = ixr_admin_xray_call('get_data');
    if (($result['success'] ?? false) !== true) {
        throw new RuntimeException((string)($result['error'] ?? '无法读取 Xray 线路数据'));
    }
    return $result;
}

function ixr_admin_xray_handle_api(): never
{
    header('Content-Type: application/json; charset=utf-8');
    $input = json_decode((string)file_get_contents('php://input'), true);
    if (!is_array($input)) {
        $input = [];
    }
    try {
        $result = ixr_admin_xray_call((string)($_GET['api'] ?? ''), $input);
        if (($result['success'] ?? false) !== true) {
            http_response_code(400);
        }
        echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    } catch (Throwable $error) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $error->getMessage()], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }
    exit;
}
