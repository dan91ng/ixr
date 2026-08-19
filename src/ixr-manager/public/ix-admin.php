<?php
/**
 * IX 中转管理面板 Pro Max + (暗黑毛玻璃美化版 + 极简收纳交互版)
 * 增强：完美比例排版、UUID 大字号自适应、全局分离点击交互(复制与弹窗不冲突)
 */

session_start();

function h($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

// ================= 配置区 =================
define('ADMIN_USER', getenv('IX_PANEL_ADMIN_USER') ?: 'admin');          
define('ADMIN_PASS', getenv('IX_PANEL_ADMIN_PASSWORD') ?: 'change-me');    
define('ADMIN_PASS_HASH_FILE', '/var/lib/' . 'v2' . 'ray-panel/admin_pass_hash');
define('FRONT_PASS', getenv('IX_PANEL_FRONT_PASSWORD') ?: 'change-me');
define('FRONT_PASS_HASH_FILE', '/var/lib/' . 'v2' . 'ray-panel/front_pass_hash');
define('FRONT_ENTRY_HOST', getenv('IX_PANEL_FRONT_ENTRY_HOST') ?: 'public.example.com');
define('SUB_PUBLIC_BASE_URL', getenv('IX_PANEL_PUBLIC_BASE_URL') ?: 'https://ix.example.com/');
define('SUB_SECRET_FILE', '/var/lib/' . 'v2' . 'ray-panel/sub_secret');
define('NODE_LATENCY_CACHE', '/tmp/' . 'v2' . 'ray_node_latency.json');
define('ADMIN_SUB_SECRET_FILE', '/var/lib/' . 'v2' . 'ray-panel/admin_sub_secret');
define('NODE_VISIBILITY_FILE', '/var/lib/' . 'v2' . 'ray-panel/node_visibility.json');
define('MAIN_CONFIG', '/etc/' . 'v2' . 'ray/config.json');
define('INBOUND_CONFIG', '/etc/' . 'v2' . 'ray/conf/VMess-TCP-10183.json');
define('NODE_IP_CACHE', '/tmp/' . 'v2' . 'ray_node_ips.json');
// ==========================================

// --- IXR integrated authentication ---
if (isset($_GET['sub'])) {
    outputAdminSubscription();
}
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    session_destroy(); header("Location: /"); exit;
}
if (empty($_SESSION['ixr_login'])) {
    if (isset($_GET['api'])) {
        header('Content-Type: application/json');
        http_response_code(401);
        echo json_encode(['success' => false, 'error' => 'Not logged in']);
        exit;
    }
    header('Location: /');
    exit;
}
$_SESSION['logged_in'] = true;

function readJson($path) {
    if (!file_exists($path)) throw new Exception("文件不存在: $path");
    return json_decode(file_get_contents($path), true);
}

function writeJson($path, $data) {
    if (isset($data['dns']) && empty($data['dns'])) $data['dns'] = new stdClass();
    if (isset($data['stats']) && empty($data['stats'])) $data['stats'] = new stdClass();
    if (isset($data['policy']['levels'])) $data['policy']['levels'] = (object)$data['policy']['levels'];
    file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function generateUuid() {
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex(random_bytes(16)), 4));
}

function getPasswordHash($path, $defaultPassword) {
    if (file_exists($path)) return trim(file_get_contents($path));
    return password_hash($defaultPassword, PASSWORD_DEFAULT);
}

function verifyStoredPassword($path, $defaultPassword, $password) {
    return password_verify($password, getPasswordHash($path, $defaultPassword));
}

function savePasswordHash($path, $password) {
    if (strlen($password) < 6) throw new Exception("密码至少需要 6 位");
    file_put_contents($path, password_hash($password, PASSWORD_DEFAULT));
    @chmod($path, 0600);
}

function getNodeVisibility() {
    if (!file_exists(NODE_VISIBILITY_FILE)) return [];
    $data = json_decode(file_get_contents(NODE_VISIBILITY_FILE), true);
    return is_array($data) ? $data : [];
}

function isNodeVisibleOnFront($tag, $visibility) {
    return !array_key_exists($tag, $visibility) || $visibility[$tag] !== false;
}

function saveNodeVisibility($tag, $showOnFront) {
    $visibility = getNodeVisibility();
    $visibility[$tag] = (bool)$showOnFront;
    file_put_contents(NODE_VISIBILITY_FILE, json_encode($visibility, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    @chmod(NODE_VISIBILITY_FILE, 0600);
}

function getNodeLatencies($nodes) {
    $cache = ['time' => 0, 'items' => []];
    if (file_exists(NODE_LATENCY_CACHE)) {
        $decoded = json_decode(file_get_contents(NODE_LATENCY_CACHE), true);
        if (is_array($decoded)) $cache = array_merge($cache, $decoded);
    }
    if (time() - ($cache['time'] ?? 0) < 300 && !empty($cache['items'])) return $cache['items'];

    $items = [];
    foreach ($nodes as $node) {
        $tag = $node['tag'] ?? '';
        $address = $node['settings']['vnext'][0]['address'] ?? '';
        if (!$tag || !$address) continue;
        $target = escapeshellarg($address);
        $output = shell_exec("ping -c 1 -W 1 $target 2>/dev/null");
        if (is_string($output) && preg_match('/time=([0-9.]+)\\s*ms/', $output, $m)) {
            $items[$tag] = round((float)$m[1]) . 'ms';
        } else {
            $items[$tag] = '超时';
        }
    }
    file_put_contents(NODE_LATENCY_CACHE, json_encode(['time' => time(), 'items' => $items], JSON_UNESCAPED_UNICODE));
    return $items;
}

function getSubscriptionSecret() {
    if (file_exists(SUB_SECRET_FILE)) return trim(file_get_contents(SUB_SECRET_FILE));
    $secret = bin2hex(random_bytes(32));
    file_put_contents(SUB_SECRET_FILE, $secret);
    @chmod(SUB_SECRET_FILE, 0600);
    return $secret;
}

function currentSubscriptionToken() {
    return substr(hash_hmac('sha256', date('Ym'), getSubscriptionSecret()), 0, 32);
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

function buildPanelData() {
    $mainData = readJson(MAIN_CONFIG);
    $inboundData = readJson(INBOUND_CONFIG);
    
    $clients = $inboundData['inbounds'][0]['settings']['clients'] ?? [];
    $inboundPort = $inboundData['inbounds'][0]['port'] ?? '未知';
    
    $nodes = array_values(array_filter($mainData['outbounds'], fn($o) => !in_array($o['tag'], ['direct', 'block', 'api'])));
    $visibility = getNodeVisibility();
    $realIps = file_exists(NODE_IP_CACHE) ? json_decode(file_get_contents(NODE_IP_CACHE), true) : [];
    $latencies = getNodeLatencies($nodes);

    $bindings = [];
    foreach ($mainData['routing']['rules'] as $rule) {
        if (isset($rule['outboundTag']) && isset($rule['user'][0]) && strpos($rule['inboundTag'][0] ?? '', 'test_proxy_') !== 0) {
            $bindings[$rule['outboundTag']] = $rule['user'][0];
        }
    }

    $clientsByEmail = [];
    foreach ($clients as $client) {
        if (!empty($client['email'])) $clientsByEmail[$client['email']] = $client['id'] ?? '';
    }

    foreach ($nodes as &$node) {
        $address = $node['settings']['vnext'][0]['address'] ?? '';
        $exitIp = $realIps[$node['tag']] ?? '待探测 (点击右上角)';
        $landingIp = '';
        if ($address) {
            $landingIp = filter_var($address, FILTER_VALIDATE_IP) ? $address : gethostbyname($address);
            if (!filter_var($landingIp, FILTER_VALIDATE_IP)) $landingIp = '';
        }
        $probeResult = '待探测';
        if (filter_var($exitIp, FILTER_VALIDATE_IP) && $landingIp) {
            $probeResult = $exitIp === $landingIp ? '一致' : '不一致';
        } elseif (!$landingIp) {
            $probeResult = '解析失败';
        }

        $frontendEmail = $bindings[$node['tag']] ?? '';
        $node['config_ip'] = $address;
        $node['landing_ip'] = $landingIp;
        $node['config_port'] = $node['settings']['vnext'][0]['port'] ?? '';
        $node['latency'] = $latencies[$node['tag']] ?? '待探测';
        $node['exit_ip'] = $exitIp;
        $node['probe_result'] = $probeResult;
        $node['uuid'] = $node['settings']['vnext'][0]['users'][0]['id'] ?? '';
        $node['frontend_email'] = $frontendEmail;
        $node['frontend_uuid'] = $clientsByEmail[$frontendEmail] ?? '';
        $node['show_on_front'] = isNodeVisibleOnFront($node['tag'] ?? '', $visibility);
    }
    unset($node);

    return ['success' => true, 'clients' => $clients, 'nodes' => $nodes, 'bindings' => $bindings, 'inbound_port' => $inboundPort];
}

function syncTestPorts($mainData) {
    $mainData['inbounds'] = array_values(array_filter($mainData['inbounds'], fn($in) => strpos($in['tag'] ?? '', 'test_proxy_') !== 0));
    $mainData['routing']['rules'] = array_values(array_filter($mainData['routing']['rules'], fn($r) => !(isset($r['inboundTag'][0]) && strpos($r['inboundTag'][0], 'test_proxy_') === 0)));

    $nodes = array_filter($mainData['outbounds'], fn($o) => !in_array($o['tag'], ['direct', 'block', 'api']));
    $portCounter = 30000;
    foreach ($nodes as $node) {
        $tag = $node['tag'];
        $testTag = "test_proxy_" . $tag;
        $mainData['inbounds'][] = ["tag" => $testTag, "port" => $portCounter, "listen" => "127.0.0.1", "protocol" => "socks", "settings" => ["auth" => "noauth", "udp" => false]];
        array_unshift($mainData['routing']['rules'], ["type" => "field", "inboundTag" => [$testTag], "outboundTag" => $tag]);
        $portCounter++;
    }
    return $mainData;
}

// --- 后端 API 逻辑 ---
if (isset($_GET['api'])) {
    header('Content-Type: application/json');
    try {
        $action = $_GET['api'];
        $input = json_decode(file_get_contents('php://input'), true);

        if ($action === 'get_data') {
            echo json_encode(buildPanelData());
            exit;
        }

        if ($action === 'change_password') {
            throw new Exception('IX Admin uses the IXR unified login session. Change the IXR password from deployment configuration.');
        }

        if ($action === 'edit_inbound_port') {
            $newPort = (int)trim($input['new_port'] ?? '');
            if (!$newPort || $newPort <= 0 || $newPort > 65535) throw new Exception("端口必须在 1-65535 之间");
            $inboundData = readJson(INBOUND_CONFIG);
            $inboundData['inbounds'][0]['port'] = $newPort;
            writeJson(INBOUND_CONFIG, $inboundData);
            echo json_encode(['success' => true, 'message' => "主监听端口修改成功"]); exit;
        }

        // 聚合节点修改接口
        if ($action === 'edit_node') {
            $oldTag = $input['old_tag'] ?? '';
            $newTag = trim($input['new_tag'] ?? '');
            $newAddress = trim($input['new_address'] ?? '');
            $newPort = (int)trim($input['new_port'] ?? '');
            $newUuid = trim($input['new_uuid'] ?? '');
            $showOnFront = !empty($input['show_on_front']);

            if (!$oldTag) throw new Exception("系统错误：原标签丢失");
            if (!$newTag) $newTag = $oldTag;
            if (!preg_match('/^[a-zA-Z0-9_-]+$/', $newTag)) throw new Exception("标签只能包含字母、数字、下划线和中划线");
            if (!$newAddress || preg_match('/\s/', $newAddress)) throw new Exception("落地地址不能为空，且不能包含空格");
            if ($newPort <= 0 || $newPort > 65535) throw new Exception("无效的端口号");
            if (!$newUuid) throw new Exception("落地节点 UUID 不能为空，请填写对端 vmess 配置里的 id");
            if (!preg_match('/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/', $newUuid)) throw new Exception("落地节点 UUID 格式不正确");

            $mainData = readJson(MAIN_CONFIG);
            $inboundData = readJson(INBOUND_CONFIG);

            if ($oldTag !== $newTag) {
                foreach ($mainData['outbounds'] as $out) { if ($out['tag'] === $newTag) throw new Exception("新标签名称已存在"); }
            }

            $oldEmail = ""; $newEmail = strtolower($newTag) . '@' . 'v2' . 'ray.com'; $found = false;

            foreach ($mainData['outbounds'] as &$out) {
                if ($out['tag'] === $oldTag) {
                    $out['tag'] = $newTag;
                    if (isset($out['settings']['vnext'][0]['address'])) $out['settings']['vnext'][0]['address'] = $newAddress;
                    if (isset($out['settings']['vnext'][0]['port'])) $out['settings']['vnext'][0]['port'] = $newPort;
                    if (isset($out['settings']['vnext'][0]['users'][0]['id'])) $out['settings']['vnext'][0]['users'][0]['id'] = $newUuid;
                    $found = true; break;
                }
            }
            unset($out);
            if (!$found) throw new Exception("未找到对应的节点");

            foreach ($mainData['routing']['rules'] as &$rule) {
                if (isset($rule['outboundTag']) && $rule['outboundTag'] === $oldTag) {
                    $rule['outboundTag'] = $newTag;
                    if (!empty($rule['user'][0])) $oldEmail = $rule['user'][0];
                }
            }
            unset($rule);

            if ($oldEmail && $oldTag !== $newTag) {
                foreach ($mainData['routing']['rules'] as &$rule) {
                    if (isset($rule['user']) && in_array($oldEmail, $rule['user'])) {
                        $rule['user'] = array_map(fn($e) => $e === $oldEmail ? $newEmail : $e, $rule['user']);
                    }
                }
                unset($rule);
                foreach ($inboundData['inbounds'][0]['settings']['clients'] as &$client) {
                    if ($client['email'] === $oldEmail) $client['email'] = $newEmail;
                }
                unset($client);
            }

            $visibility = getNodeVisibility();
            if ($oldTag !== $newTag && array_key_exists($oldTag, $visibility)) {
                unset($visibility[$oldTag]);
                file_put_contents(NODE_VISIBILITY_FILE, json_encode($visibility, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
                @chmod(NODE_VISIBILITY_FILE, 0600);
            }
            saveNodeVisibility($newTag, $showOnFront);

            writeJson(MAIN_CONFIG, $mainData); writeJson(INBOUND_CONFIG, $inboundData);
            echo json_encode(['success' => true, 'message' => "节点信息更新成功"]); exit;
        }

        if ($action === 'update_binding') {
            $tag = $input['tag']; $email = $input['email'] ?? ''; 
            $mainData = readJson(MAIN_CONFIG);
            foreach ($mainData['routing']['rules'] as $key => $rule) {
                if (isset($rule['outboundTag']) && $rule['outboundTag'] === $tag && isset($rule['user'])) unset($mainData['routing']['rules'][$key]);
            }
            $mainData['routing']['rules'] = array_values($mainData['routing']['rules']);
            if (!empty($email)) array_unshift($mainData['routing']['rules'], ["type" => "field", "inboundTag" => ["mixed"], "outboundTag" => $tag, "user" => [$email]]);
            writeJson(MAIN_CONFIG, $mainData);
            echo json_encode(['success' => true, 'message' => "绑定更新成功"]); exit;
        }

        if ($action === 'add_node_from_uri') {
            $uri = trim($input['uri'] ?? '');
            if (strpos($uri, 'vmess://') !== 0) throw new Exception("无效的 vmess 链接");
            $nodeInfo = json_decode(base64_decode(substr($uri, 8)), true);
            if (!$nodeInfo) throw new Exception("链接解析失败");
            $tag = !empty($nodeInfo['ps']) ? preg_replace('/[^a-zA-Z0-9_-]/', '', $nodeInfo['ps']) : 'node_' . time();
            $newUuid = generateUuid(); $email = strtolower($tag) . '@' . 'v2' . 'ray.com';
            $mainData = readJson(MAIN_CONFIG); $inboundData = readJson(INBOUND_CONFIG);
            $mainData['outbounds'][] = ["tag" => $tag, "protocol" => "vmess", "settings" => ["vnext" => [["address" => $nodeInfo['add'], "port" => (int)$nodeInfo['port'], "users" => [["id" => $nodeInfo['id'], "alterId" => 0, "security" => "auto"]]]]], "streamSettings" => ["network" => $nodeInfo['net'] ?? "tcp"], "mux" => ["enabled" => false]];
            array_unshift($mainData['routing']['rules'], ["type" => "field", "inboundTag" => ["mixed"], "outboundTag" => $tag, "user" => [$email]]);
            $inboundData['inbounds'][0]['settings']['clients'][] = ["id" => $newUuid, "level" => 0, "email" => $email];
            writeJson(MAIN_CONFIG, $mainData); writeJson(INBOUND_CONFIG, $inboundData);
            echo json_encode(['success' => true, 'message' => "节点添加成功"]); exit;
        }

        if ($action === 'edit_client_uuid') {
            $email = $input['email'] ?? ''; $newUuid = trim($input['new_uuid'] ?? '');
            if (!$email) throw new Exception("邮箱标识不能为空");
            if (empty($newUuid)) $newUuid = generateUuid();
            $inboundData = readJson(INBOUND_CONFIG); $found = false;
            foreach ($inboundData['inbounds'][0]['settings']['clients'] as &$client) {
                if ($client['email'] === $email) { $client['id'] = $newUuid; $found = true; break; }
            }
            if (!$found) throw new Exception("未找到对应的前端用户");
            writeJson(INBOUND_CONFIG, $inboundData);
            echo json_encode(['success' => true, 'message' => "前端用户 UUID 已更新"]); exit;
        }

        if ($action === 'delete_node') {
            $tag = $input['tag']; $mainData = readJson(MAIN_CONFIG); $inboundData = readJson(INBOUND_CONFIG);
            $emailToRemove = "";
            $mainData['outbounds'] = array_values(array_filter($mainData['outbounds'], fn($o) => $o['tag'] !== $tag));
            foreach ($mainData['routing']['rules'] as $key => $rule) {
                if (isset($rule['outboundTag']) && $rule['outboundTag'] === $tag && isset($rule['user'])) {
                    $emailToRemove = $rule['user'][0] ?? ""; unset($mainData['routing']['rules'][$key]);
                }
            }
            $mainData['routing']['rules'] = array_values($mainData['routing']['rules']);
            $isEmailUsedElsewhere = false;
            if (!empty($emailToRemove)) {
                foreach ($mainData['routing']['rules'] as $rule) { if (isset($rule['user']) && in_array($emailToRemove, $rule['user'])) { $isEmailUsedElsewhere = true; break; } }
            }
            if (!empty($emailToRemove) && !$isEmailUsedElsewhere) {
                foreach ($inboundData['inbounds'][0]['settings']['clients'] as $key => $client) { if ($client['email'] === $emailToRemove) unset($inboundData['inbounds'][0]['settings']['clients'][$key]); }
                $inboundData['inbounds'][0]['settings']['clients'] = array_values($inboundData['inbounds'][0]['settings']['clients']);
                writeJson(INBOUND_CONFIG, $inboundData);
            }
            writeJson(MAIN_CONFIG, $mainData);
            echo json_encode(['success' => true, 'message' => "节点已彻底清理"]); exit;
        }

        if ($action === 'restart_service') {
            $mainData = readJson(MAIN_CONFIG);
            $mainData = syncTestPorts($mainData);
            writeJson(MAIN_CONFIG, $mainData);
            exec('sudo /usr/bin/systemctl restart ' . escapeshellarg('v2' . 'ray') . ' > /dev/null 2>&1 &');
            sleep(1);
            echo json_encode(['success' => true, 'message' => "配置已保存，服务正在后台平滑重启"]);
            exit;
        }

        if ($action === 'test_node_ips') {
            $mainData = readJson(MAIN_CONFIG);
            $nodes = array_filter($mainData['outbounds'], fn($o) => !in_array($o['tag'], ['direct', 'block', 'api']));
            $portMap = [];
            foreach ($mainData['inbounds'] as $in) {
                if (strpos($in['tag'] ?? '', 'test_proxy_') === 0) {
                    $portMap[substr($in['tag'], 11)] = $in['port'];
                }
            }

            $mh = curl_multi_init(); $ch_list = []; $results = [];
            foreach ($nodes as $node) {
                $tag = $node['tag'];
                if (isset($portMap[$tag])) {
                    $ch = curl_init();
                    curl_setopt($ch, CURLOPT_URL, "http://api.ipify.org");
                    curl_setopt($ch, CURLOPT_PROXY, "127.0.0.1:" . $portMap[$tag]);
                    curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    curl_setopt($ch, CURLOPT_TIMEOUT, 6);
                    curl_multi_add_handle($mh, $ch);
                    $ch_list[$tag] = $ch;
                } else { $results[$tag] = "端口未分配，请先重启"; }
            }

            $running = null;
            do { curl_multi_exec($mh, $running); curl_multi_select($mh); } while ($running > 0);

            foreach ($ch_list as $tag => $ch) {
                $ip = trim(curl_multi_getcontent($ch));
                $results[$tag] = filter_var($ip, FILTER_VALIDATE_IP) ? $ip : "获取超时或不通";
                curl_multi_remove_handle($mh, $ch); curl_close($ch);
            }
            curl_multi_close($mh);

            file_put_contents(NODE_IP_CACHE, json_encode($results));
            echo json_encode(['success' => true, 'message' => "真实出口 IP 探测完毕"]);
            exit;
        }
    } catch (Exception $e) {
        http_response_code(400); echo json_encode(['success' => false, 'error' => $e->getMessage()]); exit;
    }
}

function display_login_page($error) {
    ?>
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="utf-8"><title>Panel Login</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>.glass { background: rgba(255, 255, 255, 0.05); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.1); }</style>
    </head>
    <body class="bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 flex items-center justify-center min-h-screen font-sans">
        <div class="absolute inset-0 overflow-hidden pointer-events-none">
            <div class="absolute -top-40 -right-40 w-96 h-96 bg-purple-500 rounded-full mix-blend-multiply filter blur-[128px] opacity-20"></div>
            <div class="absolute -bottom-40 -left-40 w-96 h-96 bg-indigo-500 rounded-full mix-blend-multiply filter blur-[128px] opacity-20"></div>
        </div>
        <form method="POST" class="glass p-10 rounded-3xl shadow-2xl w-[400px] z-10 text-white relative">
            <div class="mb-8 text-center">
                <div class="w-16 h-16 bg-gradient-to-tr from-indigo-500 to-purple-500 rounded-2xl mx-auto mb-4 flex items-center justify-center shadow-lg">
                    <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                </div>
                <h2 class="text-3xl font-extrabold tracking-tight">IX Matrix</h2>
            </div>
            <?php if($error): ?>
                <div class="bg-red-500/20 border border-red-500/50 text-red-200 px-4 py-3 rounded-xl mb-6 text-sm flex items-center backdrop-blur-md">
                    <svg class="w-5 h-5 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <?= $error ?>
                </div>
            <?php endif; ?>
            <div class="space-y-4">
                <input type="text" name="user" placeholder="Username" class="w-full bg-slate-900/50 border border-slate-700 text-white px-5 py-3 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none transition" required>
                <input type="password" name="pass" placeholder="Password" class="w-full bg-slate-900/50 border border-slate-700 text-white px-5 py-3 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none transition" required>
            </div>
            <button type="submit" name="login" class="w-full bg-gradient-to-r from-indigo-500 to-purple-600 text-white font-bold py-3.5 rounded-xl hover:from-indigo-400 hover:to-purple-500 shadow-lg shadow-indigo-500/30 transition-all mt-8">Secure Login</button>
        </form>
    </body>
    </html>
    <?php
}

function display_front_login_page($error) {
    ?>
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="utf-8"><title>HKIX Front</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>.glass { background: rgba(255, 255, 255, 0.05); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.1); }</style>
    </head>
    <body class="bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 flex items-center justify-center min-h-screen font-sans">
        <div class="absolute inset-0 overflow-hidden pointer-events-none">
            <div class="absolute -top-40 -right-40 w-96 h-96 bg-purple-500 rounded-full mix-blend-multiply filter blur-[128px] opacity-20"></div>
            <div class="absolute -bottom-40 -left-40 w-96 h-96 bg-indigo-500 rounded-full mix-blend-multiply filter blur-[128px] opacity-20"></div>
        </div>
        <form method="POST" class="glass p-10 rounded-3xl shadow-2xl w-[400px] z-10 text-white relative">
            <div class="mb-8 text-center">
                <div class="w-16 h-16 bg-gradient-to-tr from-indigo-500 to-purple-500 rounded-2xl mx-auto mb-4 flex items-center justify-center shadow-lg">
                    <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                </div>
                <h2 class="text-3xl font-extrabold tracking-tight">HKIX Front</h2>
                <p class="text-slate-400 text-sm mt-2">落地节点配置</p>
            </div>
            <?php if($error): ?>
                <div class="bg-red-500/20 border border-red-500/50 text-red-200 px-4 py-3 rounded-xl mb-6 text-sm flex items-center backdrop-blur-md"><?= $error ?></div>
            <?php endif; ?>
            <input type="password" name="front_pass" placeholder="Password" class="w-full bg-slate-900/50 border border-slate-700 text-white px-5 py-3 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none transition" required>
            <button type="submit" name="front_login" class="w-full bg-gradient-to-r from-indigo-500 to-purple-600 text-white font-bold py-3.5 rounded-xl hover:from-indigo-400 hover:to-purple-500 shadow-lg shadow-indigo-500/30 transition-all mt-8">Open Front Page</button>
        </form>
    </body>
    </html>
    <?php
}

function display_front_page() {
    $data = buildPanelData();
    ?>
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8"><title>HKIX Front - 落地节点配置</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body { font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: #f8fafc; }
            .glass-nav { background: rgba(30, 41, 59, 0.85); backdrop-filter: blur(12px); border-bottom: 1px solid rgba(255,255,255,0.1); }
            .table-header { background: rgba(248, 250, 252, 0.9); backdrop-filter: blur(4px); }
            .custom-scrollbar::-webkit-scrollbar { width: 6px; height: 6px; }
            .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
            .custom-scrollbar::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 10px; }
        </style>
    </head>
    <body class="text-slate-800 antialiased selection:bg-indigo-100 selection:text-indigo-900 pb-16">
        <nav class="glass-nav text-white px-6 py-4 sticky top-0 z-40 shadow-sm">
            <div class="max-w-[1200px] mx-auto flex flex-col sm:flex-row justify-between items-center gap-4">
                <div class="flex items-center gap-5">
                    <div class="text-2xl font-black tracking-tight bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent flex items-center">
                        <i class="fa-solid fa-bolt mr-2 text-indigo-400"></i>HKIX Front
                    </div>
                    <div class="hidden md:flex text-sm bg-slate-800/80 px-4 py-2 rounded-xl border border-slate-700 shadow-inner items-center">
                        <i class="fa-solid fa-satellite-dish mr-2 text-indigo-400"></i>
                        <span class="text-slate-300 mr-2">入口:</span>
                        <span class="font-mono tracking-wider font-bold text-base text-white"><?= FRONT_ENTRY_HOST ?>:<?= htmlspecialchars($data['inbound_port']) ?></span>
                    </div>
                </div>
                <a href="?action=front_logout" class="bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white px-4 py-2.5 rounded-xl transition-all flex items-center" title="安全退出">
                    <i class="fa-solid fa-power-off"></i>
                </a>
            </div>
        </nav>

        <div class="max-w-[1200px] mx-auto mt-8 px-4">
            <div class="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden hover:shadow-md transition-shadow">
                <div class="p-5 border-b border-slate-100 flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3 bg-slate-50/50">
                    <h3 class="font-bold text-slate-800 text-lg flex items-center"><i class="fa-solid fa-server mr-2 text-blue-500 bg-blue-50 p-2 rounded-lg"></i>落地节点配置</h3>
                    <span class="text-xs font-medium text-slate-500 bg-white border px-3 py-1 rounded-full shadow-sm">点击行或复制按钮获取本地节点配置</span>
                </div>
                <div class="overflow-x-auto custom-scrollbar">
                    <table class="w-full text-left border-collapse">
                        <thead class="table-header text-slate-500 text-xs font-bold uppercase tracking-wider sticky top-0 z-10">
                            <tr>
                                <th class="px-5 py-4 border-b border-slate-200">节点</th>
                                <th class="px-5 py-4 border-b border-slate-200">落地地址 / 出口IP</th>
                                <th class="px-5 py-4 border-b border-slate-200">前端用户</th>
                                <th class="px-5 py-4 border-b border-slate-200 text-center">复制</th>
                            </tr>
                        </thead>
                        <tbody id="frontNodeTable" class="divide-y divide-slate-100 text-sm"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="toast" class="fixed bottom-6 right-6 transform translate-y-24 opacity-0 transition-all duration-300 ease-out px-6 py-4 rounded-xl shadow-2xl z-50 flex items-center gap-3 text-white font-medium max-w-md pointer-events-none border border-white/10 backdrop-blur-md"></div>

        <script>
            const frontData = <?= json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;
            const FRONT_ENTRY_HOST = <?= json_encode(FRONT_ENTRY_HOST) ?>;
            const currentInboundPort = frontData.inbound_port || "10183";

            function encodeBase64Utf8(text) {
                return btoa(unescape(encodeURIComponent(text)));
            }

            function makeVmess(node) {
                if (!node.frontend_uuid) return '';
                const config = {
                    v: "2",
                    ps: `HKIX|${node.tag}-${node.config_ip}`,
                    add: FRONT_ENTRY_HOST,
                    port: String(currentInboundPort),
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
                return `vmess://${encodeBase64Utf8(JSON.stringify(config, null, 2))}`;
            }

            function copyNodeConfig(tag) {
                const node = frontData.nodes.find(n => n.tag === tag);
                if (!node) return showToast('未找到对应落地节点', 'error');
                const link = makeVmess(node);
                if (!link) return showToast('该节点未绑定前端用户，无法生成配置', 'error');
                navigator.clipboard.writeText(link).then(() => showToast(`已复制 ${node.tag} 的客户端配置`)).catch(() => showToast('复制失败，请手动选择复制', 'error'));
            }

            function renderFrontNodes() {
                document.getElementById('frontNodeTable').innerHTML = frontData.nodes.map(node => {
                    let isError = node.exit_ip.includes("超时") || node.exit_ip.includes("未分配") || node.exit_ip.includes("待探测");
                    let statusDot = isError ? `<span class="w-2 h-2 rounded-full bg-red-500 mr-1.5 animate-pulse"></span>` : `<span class="w-2 h-2 rounded-full bg-emerald-500 mr-1.5"></span>`;
                    let exitIpColor = isError ? "text-slate-500" : "text-emerald-600 font-bold";
                    let probeClass = node.probe_result === '一致' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : (node.probe_result === '不一致' ? 'bg-red-50 text-red-700 border-red-200' : 'bg-slate-100 text-slate-500 border-slate-200');
                    return `<tr class="hover:bg-indigo-50/60 transition-colors cursor-pointer group border-b border-transparent hover:border-indigo-100" onclick="copyNodeConfig('${node.tag}')">
                        <td class="px-5 py-4 whitespace-nowrap">
                            <div class="font-bold text-slate-800 text-[15px] group-hover:text-indigo-600 transition-colors">${node.tag}</div>
                            <div class="font-mono text-[12px] text-slate-500 mt-1 opacity-80">${node.uuid}</div>
                        </td>
                        <td class="px-5 py-4 whitespace-nowrap text-sm">
                            <div class="text-slate-500 mb-1.5 flex items-center"><i class="fa-solid fa-arrow-right-to-bracket text-slate-300 mr-2 w-4"></i><span class="font-mono">${node.config_ip} ? <span class="font-bold text-slate-700">${node.latency}</span></span></div>
                            <div class="flex items-center text-sm"><i class="fa-solid fa-globe text-slate-300 mr-2 w-4"></i>${statusDot}<span class="font-mono ${exitIpColor}">${node.exit_ip}</span><span class="ml-2 px-2 py-0.5 rounded-full border text-[11px] font-bold ${probeClass}">${node.probe_result}</span></div>
                        </td>
                        <td class="px-5 py-4 whitespace-nowrap">
                            <div class="font-medium text-slate-700">${node.frontend_email || '未绑定'}</div>
                            <div class="font-mono text-[12px] text-slate-500 mt-1">${node.frontend_uuid || ''}</div>
                        </td>
                        <td class="px-5 py-4 text-center whitespace-nowrap">
                            <button onclick="event.stopPropagation(); copyNodeConfig('${node.tag}')" class="text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 p-2.5 rounded-xl transition-all outline-none" title="复制本地客户端 vmess 配置"><i class="fa-solid fa-copy"></i></button>
                        </td>
                    </tr>`;
                }).join('');
            }

            function showToast(msg, type="success") {
                const t = document.getElementById('toast');
                const icon = type === 'success' ? '<i class="fa-solid fa-circle-check text-xl"></i>' : '<i class="fa-solid fa-circle-xmark text-xl"></i>';
                const bgClass = type === 'success' ? 'bg-slate-800/95 border-emerald-500/50 text-white' : 'bg-red-500/95 border-red-400 text-white shadow-red-500/30';
                t.innerHTML = `${icon} <span>${msg}</span>`;
                t.className = `fixed bottom-8 right-8 transform translate-y-0 opacity-100 transition-all duration-400 ease-out px-6 py-4 rounded-2xl shadow-2xl z-50 flex items-center gap-3 font-medium max-w-md pointer-events-none border backdrop-blur-xl ${bgClass}`;
                setTimeout(() => { t.classList.replace('translate-y-0', 'translate-y-12'); t.classList.replace('opacity-100', 'opacity-0'); }, 3500);
            }

            renderFrontNodes();
        </script>
    </body>
    </html>
    <?php
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8"><title>IX Matrix - 管理面板</title>
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
        body.ix-admin-integrated .ix-port-pill { margin-top:12px; display:inline-flex; align-items:center; gap:9px; border:1px solid rgba(255,255,255,.22); background:rgba(15,23,42,.24); color:#fff; border-radius:999px; padding:8px 12px; font-size:13px; font-weight:900; }
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
        @media (max-width: 900px) { body.ix-admin-integrated .ix-hero-inner { flex-direction:column; align-items:flex-start; } body.ix-admin-integrated .ix-toolbar { justify-content:flex-start; } body.ix-admin-integrated .ix-action-label { display:none; } }
    </style>
</head>
<body class="text-slate-800 antialiased selection:bg-indigo-100 selection:text-indigo-900 pb-16 relative ix-admin-integrated" data-embedded="<?=isset($_GET['embedded']) ? '1' : '0'?>">
    
    <nav class="glass-nav">
        <div class="ix-hero-inner">
            <div>
                <div class="ix-kicker"><i class="fa-solid fa-diagram-project"></i>Legacy IX / V2Ray</div>
                <h1 class="ix-hero-title"><i class="fa-solid fa-bolt"></i>IX Admin</h1>
                <p class="ix-hero-subtitle">管理原 IX 中转节点、前端用户绑定和订阅导出。</p>
                <button type="button" id="inboundPortBtn" onclick="editInboundPort()" class="ix-port-pill" title="点击修改主监听端口">
                    <i class="fa-solid fa-satellite-dish"></i><span>监听端口</span><b id="inboundPort">---</b>
                </button>
            </div>
            <div class="ix-toolbar">
                <a href="/" class="ix-action" title="返回 IXR"><i class="fa-solid fa-house"></i><span class="ix-action-label">返回 IXR</span></a>
                <button id="testIpBtn" onclick="testNodeIps()" class="ix-action" title="穿透测速"><i class="fa-solid fa-network-wired"></i><span class="ix-action-label">穿透测速</span></button>
                <button id="rebootBtn" onclick="restartService()" class="ix-action primary" title="保存并重启"><i class="fa-solid fa-rotate"></i><span class="ix-action-label">保存并重启</span></button>
                <button onclick="copySubscriptionUrl()" class="ix-action" title="复制订阅"><i class="fa-solid fa-rss"></i><span class="ix-action-label">订阅</span></button>
                <a href="<?=h(getenv('IX_PANEL_GRAFANA_URL') ?: '#')?>" target="_blank" rel="noopener noreferrer" class="ix-action" title="Grafana 监控"><i class="fa-solid fa-chart-line"></i><span class="ix-action-label">监控</span></a>
                <a href="?action=logout" class="ix-action danger" title="安全退出"><i class="fa-solid fa-power-off"></i><span class="ix-action-label">退出</span></a>
            </div>
        </div>
    </nav>

    <div class="ix-admin-summary">
        <div class="ix-admin-metric"><i class="fa-solid fa-server"></i><div><span>落地节点</span><b id="ixNodeCount">--</b></div></div>
        <div class="ix-admin-metric"><i class="fa-solid fa-users"></i><div><span>前端用户</span><b id="ixClientCount">--</b></div></div>
        <div class="ix-admin-metric"><i class="fa-solid fa-link"></i><div><span>绑定关系</span><b id="ixBoundCount">--</b></div></div>
        <div class="ix-admin-metric"><i class="fa-solid fa-satellite-dish"></i><div><span>监听端口</span><b id="ixInboundMetric">--</b></div></div>
    </div>

    <!-- 主容器 -->
    <div class="ix-admin-layout max-w-[1500px] mx-auto mt-8 px-4 grid grid-cols-1 xl:grid-cols-12 gap-8">
        
        <!-- 左侧：节点与路由区 (比例 7) -->
        <div class="xl:col-span-7 space-y-6">
            
            <div class="ix-card bg-white p-6 rounded-2xl shadow-sm border border-slate-200 hover:shadow-md transition-shadow">
                <div class="flex items-center justify-between mb-5">
                    <h3 class="font-bold text-slate-800 text-lg flex items-center"><i class="fa-solid fa-link mr-2 text-indigo-500 bg-indigo-50 p-2 rounded-lg"></i>快速导入落地节点</h3>
                </div>
                <div class="flex gap-3 relative">
                    <div class="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none"><i class="fa-solid fa-paste text-slate-400"></i></div>
                    <input type="text" id="vmessInput" placeholder="在此粘贴 vmess:// 链接..." class="flex-1 bg-slate-50 border border-slate-200 rounded-xl pl-11 pr-4 py-3 focus:bg-white focus:ring-2 focus:ring-indigo-500 outline-none transition-all text-sm shadow-inner">
                    <button onclick="addNode()" class="bg-slate-800 text-white px-8 py-3 rounded-xl hover:bg-slate-700 transition shadow-md font-medium whitespace-nowrap flex items-center">
                        <i class="fa-solid fa-plus mr-2"></i>添加
                    </button>
                </div>
            </div>

            <div class="ix-card bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden hover:shadow-md transition-shadow flex flex-col">
                <div class="p-5 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
                    <h3 class="font-bold text-slate-800 text-lg flex items-center"><i class="fa-solid fa-server mr-2 text-blue-500 bg-blue-50 p-2 rounded-lg"></i>落地节点配置</h3>
                    <span class="text-xs font-medium text-slate-500 bg-white border px-3 py-1 rounded-full shadow-sm">点击行复制客户端配置 | 点击标签编辑 | 点击UUID复制</span>
                </div>
                <div class="overflow-x-auto custom-scrollbar">
                    <table class="w-full text-left border-collapse">
                        <thead class="table-header text-slate-500 text-xs font-bold uppercase tracking-wider sticky top-0 z-10">
                            <tr>
                                <th class="px-5 py-4 border-b border-slate-200">节点标签 & 落地 UUID</th>
                                <th class="px-5 py-4 border-b border-slate-200">落地地址 / 出口IP</th>
                                <th class="px-5 py-4 border-b border-slate-200 min-w-[200px]">绑定前端用户</th>
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

    <!-- 弹窗：编辑节点 -->
    <div id="nodeModal" class="fixed inset-0 bg-slate-900/60 backdrop-blur-sm hidden items-center justify-center z-50 transition-opacity opacity-0">
        <div id="nodeModalCard" class="bg-white rounded-3xl shadow-2xl w-[420px] p-7 transform scale-95 transition-all duration-300">
            <div class="flex justify-between items-center mb-6">
                <h3 class="text-xl font-bold text-slate-800">编辑落地节点</h3>
                <button onclick="closeNodeModal()" class="text-slate-400 hover:text-slate-600"><i class="fa-solid fa-xmark text-xl"></i></button>
            </div>
            <input type="hidden" id="modalOldTag">
            <div class="space-y-4">
                <div>
                    <label class="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1.5">节点标签 (Tag)</label>
                    <input type="text" id="modalTag" class="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-sm font-medium text-slate-800 focus:bg-white focus:ring-2 focus:ring-indigo-500 outline-none transition">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1.5">落地地址 (Address)</label>
                    <input type="text" id="modalAddress" class="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-sm font-mono text-slate-700 focus:bg-white focus:ring-2 focus:ring-indigo-500 outline-none transition">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1.5">落地端口 (Port)</label>
                    <input type="number" id="modalPort" class="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-sm font-medium text-slate-800 focus:bg-white focus:ring-2 focus:ring-indigo-500 outline-none transition">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1.5">落地 UUID (VMess ID，不能为空)</label>
                    <input type="text" id="modalUuid" class="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-[13px] font-mono text-slate-600 focus:bg-white focus:ring-2 focus:ring-indigo-500 outline-none transition">
                </div>
                <label class="flex items-center justify-between bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 cursor-pointer hover:bg-white transition">
                    <span class="text-sm font-bold text-slate-700">在前台 index.php 展示</span>
                    <input type="checkbox" id="modalShowOnFront" class="w-5 h-5 accent-indigo-600">
                </label>
            </div>
            <div class="mt-8">
                <button onclick="saveNodeModal()" class="w-full bg-indigo-600 text-white font-bold py-3.5 rounded-xl hover:bg-indigo-700 transition shadow-lg shadow-indigo-500/30">确认保存</button>
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
                    <div><h3 class='text-xl font-bold text-slate-800'>选择订阅格式</h3><p class='text-sm text-slate-500 mt-1'>复制适合当前客户端的订阅链接</p></div>
                </div>
                <button onclick='closeSubscriptionModal()' class='text-slate-400 hover:text-slate-600 p-1'><i class='fa-solid fa-xmark text-xl'></i></button>
            </div>
            <div class='space-y-3'>
                <button onclick='copyV2raySubscription()' class='w-full text-left border border-slate-200 hover:border-indigo-300 hover:bg-indigo-50/60 rounded-2xl p-4 transition-all group flex items-center gap-4'>
                    <span class='w-11 h-11 rounded-xl bg-indigo-100 text-indigo-600 flex items-center justify-center group-hover:bg-indigo-600 group-hover:text-white transition-colors'><i class='fa-solid fa-link'></i></span>
                    <span class='flex-1'><span class='block font-bold text-slate-800'>V2Ray 订阅链接</span><span class='block text-xs text-slate-500 mt-1'>适用于 v2rayN、v2rayNG、Shadowrocket 等客户端</span></span>
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
        const FRONT_ENTRY_HOST = <?= json_encode(FRONT_ENTRY_HOST) ?>;
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

        function copyNodeConfig(event, tag) {
            event.stopPropagation();
            const node = nodesCache.find(n => n.tag === tag);
            if (!node) return showToast('未找到对应落地节点', 'error');
            if (!node.frontend_uuid) return showToast('请先为该落地节点绑定前端用户', 'error');

            const config = {
                v: "2",
                ps: `HKIX|${node.tag}-${node.config_ip}`,
                add: FRONT_ENTRY_HOST,
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

        function copyV2raySubscription() {
            copySubscriptionLink(SUB_URL, 'V2Ray');
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

        async function loadData() {
            const res = await fetch('?api=get_data').then(r => r.json());
            clientsCache = res.clients;
            nodesCache = res.nodes;
            currentInboundPort = res.inbound_port;
            document.getElementById('inboundPort').textContent = res.inbound_port;

            const metric = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value; };
            const boundCount = Object.values(res.bindings || {}).filter(Boolean).length;
            metric('ixNodeCount', (res.nodes || []).length);
            metric('ixClientCount', (res.clients || []).length);
            metric('ixBoundCount', boundCount);
            metric('ixInboundMetric', res.inbound_port || '--');
            
            const emailCounts = {};
            Object.values(res.bindings).forEach(email => { if (email) emailCounts[email] = (emailCounts[email] || 0) + 1; });
            
            document.getElementById('nodeTable').innerHTML = res.nodes.map(node => {
                const currentBinding = res.bindings[node.tag] || '';
                const isDuplicate = currentBinding !== '' && emailCounts[currentBinding] > 1;
                const options = clientsCache.map(c => `<option value="${c.email}" ${c.email === currentBinding ? 'selected' : ''}>${c.email}</option>`).join('');
                
                const selectClasses = isDuplicate 
                    ? 'border-red-300 focus:ring-red-500 bg-red-50 text-red-700' 
                    : 'border-slate-200 focus:ring-indigo-500 bg-slate-50 text-slate-700 hover:bg-white';
                
                const warningMsg = isDuplicate ? `<div class="text-xs text-red-500 mt-2 font-medium flex items-center"><i class="fa-solid fa-triangle-exclamation mr-1.5"></i>已绑定其他节点</div>` : '';

                let exitIpStatus = node.exit_ip;
                let isError = node.exit_ip.includes("超时") || node.exit_ip.includes("未分配") || node.exit_ip.includes("待探测");
                let statusDot = isError ? `<span class="w-2 h-2 rounded-full bg-red-500 mr-1.5 animate-pulse"></span>` : `<span class="w-2 h-2 rounded-full bg-emerald-500 mr-1.5"></span>`;
                let exitIpColor = isError ? "text-slate-500" : "text-emerald-600 font-bold";
                let probeClass = node.probe_result === '一致' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : (node.probe_result === '不一致' ? 'bg-red-50 text-red-700 border-red-200' : 'bg-slate-100 text-slate-500 border-slate-200');

                // 整行点击事件，左侧 UUID 通过 onclick="copyText..." 独立响应并拦截冒泡
                return `<tr class="hover:bg-indigo-50/60 transition-colors cursor-pointer group border-b border-transparent hover:border-indigo-100" onclick="copyNodeConfig(event, '${node.tag}')">
                    <td class="px-5 py-4 whitespace-nowrap">
                        <div class="font-bold text-slate-800 text-[15px] group-hover:text-indigo-600 hover:bg-indigo-100 inline-block px-1.5 py-1 rounded transition-colors -ml-1.5" onclick="event.stopPropagation(); openNodeModal('${node.tag}', '${node.config_ip}', '${node.config_port}', '${node.uuid}', ${node.show_on_front ? 'true' : 'false'})" title="点击编辑落地节点">${node.tag}</div>
                        <div class="font-mono text-[12px] text-slate-500 mt-1 opacity-80">
                            <span class="hover:text-indigo-600 hover:bg-indigo-100 px-1.5 py-1 rounded transition-colors -ml-1.5 inline-block" onclick="copyText(event, '${node.uuid}')" title="点击仅复制落地 UUID">${node.uuid}</span>
                        </div>
                    </td>
                    <td class="px-5 py-4 whitespace-nowrap text-sm">
                        <div class="text-slate-500 mb-1.5 flex items-center">
                            <i class="fa-solid fa-arrow-right-to-bracket text-slate-300 mr-2 w-4"></i>
                            <span class="font-mono">${node.config_ip} ? <span class="font-bold text-slate-700">${node.latency}</span></span>
                        </div>
                        <div class="flex items-center text-sm">
                            <i class="fa-solid fa-globe text-slate-300 mr-2 w-4"></i>
                            ${statusDot}
                            <span class="font-mono ${exitIpColor}">${exitIpStatus}</span>
                            <span class="ml-2 px-2 py-0.5 rounded-full border text-[11px] font-bold ${probeClass}">${node.probe_result}</span>
                        </div>
                    </td>
                    <td class="px-5 py-4" onclick="event.stopPropagation()">
                        <select onchange="updateBinding('${node.tag}', this.value)" class="border rounded-xl block w-full px-3 py-2 outline-none transition cursor-pointer text-sm font-medium ${selectClasses}">
                            <option value="">-- 未绑定 (阻断连接) --</option>
                            ${options}
                        </select>
                        ${warningMsg}
                    </td>
                    <td class="px-5 py-4 text-center whitespace-nowrap" onclick="event.stopPropagation()">
                        <button onclick="deleteNode('${node.tag}')" class="text-slate-400 hover:text-red-500 hover:bg-red-50 p-2.5 rounded-xl transition-all outline-none" title="彻底删除此节点">
                            <i class="fa-solid fa-trash-can"></i>
                        </button>
                    </td>
                </tr>`;
            }).join('');

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
        }

        // --- 模态框控制逻辑 ---
        function openNodeModal(tag, address, port, uuid, showOnFront) {
            document.getElementById('modalOldTag').value = tag;
            document.getElementById('modalTag').value = tag;
            document.getElementById('modalAddress').value = address;
            document.getElementById('modalPort').value = port;
            document.getElementById('modalUuid').value = uuid;
            document.getElementById('modalShowOnFront').checked = showOnFront !== false;
            const m = document.getElementById('nodeModal'); const c = document.getElementById('nodeModalCard');
            m.classList.remove('hidden'); m.classList.add('flex');
            setTimeout(() => { m.classList.remove('opacity-0'); c.classList.add('modal-enter'); }, 10);
        }
        function closeNodeModal() {
            const m = document.getElementById('nodeModal'); const c = document.getElementById('nodeModalCard');
            m.classList.add('opacity-0'); c.classList.remove('modal-enter');
            setTimeout(() => { m.classList.add('hidden'); m.classList.remove('flex'); }, 300);
        }
        async function saveNodeModal() {
            const oldTag = document.getElementById('modalOldTag').value;
            const newTag = document.getElementById('modalTag').value;
            const newAddress = document.getElementById('modalAddress').value;
            const newPort = document.getElementById('modalPort').value;
            const newUuid = document.getElementById('modalUuid').value;
            const showOnFront = document.getElementById('modalShowOnFront').checked;
            if (!newAddress.trim()) { showToast('落地地址不能为空', 'error'); return; }
            if (!newUuid.trim()) { showToast('落地 UUID 不能为空', 'error'); return; }
            closeNodeModal();
            const res = await fetch('?api=edit_node', {method: 'POST', body: JSON.stringify({old_tag: oldTag, new_tag: newTag, new_address: newAddress, new_port: newPort, new_uuid: newUuid, show_on_front: showOnFront})}).then(r => r.json());
            if(res.success) { showToast(`${res.message}，请重启生效`); loadData(); } else showToast(res.error, "error");
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
            if(res.success) { showToast(`${res.message}，请重启生效`); loadData(); } else showToast(res.error, "error");
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
        async function editInboundPort() {
            const input = prompt(`修改主监听端口\n\n⚠️ 请确保服务器防火墙已放行新端口。\n\n输入 1-65535 之间的数字：`, currentInboundPort);
            if (input === null || input.trim() === '' || input.trim() == currentInboundPort) return;
            const res = await fetch('?api=edit_inbound_port', {method: 'POST', body: JSON.stringify({new_port: input.trim()})}).then(r => r.json());
            if(res.success) { showToast(`${res.message}，请重启生效`); loadData(); } else showToast(res.error, "error");
        }

        async function updateBinding(tag, email) {
            const res = await fetch('?api=update_binding', {method: 'POST', body: JSON.stringify({tag, email})}).then(r => r.json());
            if(res.success) { showToast('路由调度已更新，请点击【保存并重启】生效'); loadData(); }
        }

        async function addNode() {
            const uri = document.getElementById('vmessInput').value;
            if(!uri) return showToast('请输入 vmess 链接', "error");
            const res = await fetch('?api=add_node_from_uri', {method: 'POST', body: JSON.stringify({uri})}).then(r => r.json());
            if(res.success) { showToast('节点添加成功'); loadData(); document.getElementById('vmessInput').value = ''; } else showToast(res.error, "error");
        }

        async function deleteNode(tag) {
            if(!confirm(`⚠️ 危险操作\n\n确定彻底删除 [ ${tag} ] 节点及绑定的路由吗？此操作不可恢复。`)) return;
            const res = await fetch('?api=delete_node', {method: 'POST', body: JSON.stringify({tag})}).then(r => r.json());
            if(res.success) { showToast(res.message); loadData(); }
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
            const icon = type === 'success' ? '<i class="fa-solid fa-circle-check text-xl"></i>' : '<i class="fa-solid fa-circle-xmark text-xl"></i>';
            const bgClass = type === 'success' ? 'bg-slate-800/95 border-emerald-500/50 text-white' : 'bg-red-500/95 border-red-400 text-white shadow-red-500/30';
            t.innerHTML = `${icon} <span>${msg}</span>`;
            t.className = `fixed bottom-8 right-8 transform translate-y-0 opacity-100 transition-all duration-400 ease-out px-6 py-4 rounded-2xl shadow-2xl z-50 flex items-center gap-3 font-medium max-w-md pointer-events-none border backdrop-blur-xl ${bgClass}`;
            setTimeout(() => { t.classList.replace('translate-y-0', 'translate-y-12'); t.classList.replace('opacity-100', 'opacity-0'); }, 3500);
        }

        loadData();
    </script>
</body>
</html>
