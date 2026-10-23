<?php header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');header('Pragma: no-cache');header('Expires: 0');
session_start();
require_once __DIR__ . '/lib/user_store.php';
require_once __DIR__ . '/lib/ix_admin_xray.php';
$USER=getenv('IXR_ADMIN_USER') ?: 'admin';
$PASS=getenv('IXR_ADMIN_PASSWORD') ?: 'change-me';
$base='/opt/ixr-manager/data';
$stateFile="$base/state.json";
$outFile="$base/outbounds.json";
$customOutFile=$outFile;
$exportFile="$base/export.json";
$healthFile="$base/health.json";
$usageFile="$base/usage.json";
$applyStatusFile="$base/apply_status.json";
date_default_timezone_set('Asia/Shanghai');

function h($s){ return htmlspecialchars((string)$s,ENT_QUOTES,'UTF-8'); }
function load_json($f,$d){ if(!file_exists($f)) return $d; $j=json_decode(file_get_contents($f),true); return is_array($j)?$j:$d; }
function save_json($f,$s){ file_put_contents($f,json_encode($s,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT)); }
function save_state($s){ global $stateFile; save_json($stateFile,$s); }
function save_export($s){ global $exportFile; save_json($exportFile,$s); }
function save_custom_outbounds($s){ global $customOutFile; save_json($customOutFile,$s); }
function new_uuid(){ $d=random_bytes(16); $d[6]=chr((ord($d[6])&0x0f)|0x40); $d[8]=chr((ord($d[8])&0x3f)|0x80); return vsprintf('%s%s-%s-%s-%s-%s%s%s',str_split(bin2hex($d),4)); }
function new_rule_id(){ return 'rule-'.bin2hex(random_bytes(8)); }
function safe_tag($name){ $tag=preg_replace('/[^A-Za-z0-9_.-]+/','-',trim((string)$name)); $tag=trim($tag,'-'); return $tag!==''?$tag:'node'; }
function default_smart_pools(){ return [
  ['id'=>'google','name'=>'Google智能自动','members'=>[],'keyword'=>'','builtin'=>true],
  ['id'=>'dn42','name'=>'DN42智能自动','members'=>[],'keyword'=>'DN42','builtin'=>true],
]; }
function new_pool_id($name=''){ $base=preg_replace('/[^A-Za-z0-9_.-]+/','-',trim((string)$name)); $base=trim($base,'-'); if($base==='') $base='pool'; return 'pool-'.$base.'-'.bin2hex(random_bytes(3)); }
function normalize_members($members){
  if(is_string($members)) $members=preg_split('/[\r\n,，\s]+/u',$members);
  if(!is_array($members)) $members=[];
  $out=[]; foreach($members as $m){ $m=trim((string)$m); if($m!=='' && !in_array($m,$out,true)) $out[]=$m; }
  return $out;
}
function normalize_smart_pools($pools){
  $raw=is_array($pools)?$pools:[];
  $result=[]; $usedIds=[]; $usedNames=[];
  foreach(default_smart_pools() as $def){
    $match=null; foreach($raw as $pool){ if(is_array($pool) && (($pool['id'] ?? '')===$def['id'] || ($pool['name'] ?? '')===$def['name'])){ $match=$pool; break; } }
    $members=normalize_members($match['members'] ?? $def['members']);
    $keyword=trim((string)($match['keyword'] ?? $def['keyword']));
    $result[]=['id'=>$def['id'],'name'=>$def['name'],'members'=>$members,'keyword'=>$keyword,'builtin'=>true];
    $usedIds[$def['id']]=true; $usedNames[$def['name']]=true;
  }
  foreach($raw as $pool){
    if(!is_array($pool)) continue;
    $id=trim((string)($pool['id'] ?? '')); $name=trim((string)($pool['name'] ?? ''));
    if($id==='' || !preg_match('/^[A-Za-z0-9_.:-]{3,80}$/',$id)) $id=new_pool_id($name);
    if($name==='') $name=$id;
    if(isset($usedIds[$id]) || isset($usedNames[$name])) continue;
    $result[]=['id'=>$id,'name'=>$name,'members'=>normalize_members($pool['members'] ?? []),'keyword'=>trim((string)($pool['keyword'] ?? '')),'builtin'=>false];
    $usedIds[$id]=true; $usedNames[$name]=true;
  }
  return $result;
}
function normalize_custom_outbound($item){
  if(!is_array($item)) return null;
  $name=trim((string)($item['name'] ?? ''));
  $address=trim((string)($item['address'] ?? ''));
  $id=trim((string)($item['id'] ?? $item['uuid'] ?? ''));
  $remotePort=max(0,min(65535,intval($item['remote_port'] ?? $item['server_port'] ?? $item['port'] ?? 0)));
  $probePort=max(0,min(65535,intval($item['probe_port'] ?? 0)));
  if($name==='' || $address==='' || $id==='' || $remotePort<=0 || $probePort<=0) return null;
  return [
    'name'=>$name,
    'protocol'=>'vmess',
    'address'=>$address,
    'remote_port'=>$remotePort,
    'id'=>$id,
    'aid'=>max(0,intval($item['aid'] ?? $item['alterId'] ?? 0)),
    'security'=>trim((string)($item['security'] ?? $item['scy'] ?? 'auto')) ?: 'auto',
    'network'=>trim((string)($item['network'] ?? $item['net'] ?? 'tcp')) ?: 'tcp',
    'header_type'=>trim((string)($item['header_type'] ?? $item['type'] ?? 'none')) ?: 'none',
    'host'=>trim((string)($item['host'] ?? '')),
    'path'=>trim((string)($item['path'] ?? '')),
    'tls'=>trim((string)($item['tls'] ?? '')),
    'sni'=>trim((string)($item['sni'] ?? '')),
    'alpn'=>trim((string)($item['alpn'] ?? '')),
    'fp'=>trim((string)($item['fp'] ?? $item['fingerprint'] ?? '')),
    'insecure'=>trim((string)($item['insecure'] ?? '0')),
    'probe_port'=>$probePort,
    'port'=>$probePort,
    'kind'=>'vmess',
    'tag'=>'via-'.safe_tag($name),
  ];
}
function normalize_custom_outbounds($items){
  $items=is_array($items)?$items:[];
  $out=[]; $seen=[];
  foreach($items as $item){
    $clean=normalize_custom_outbound($item);
    if(!$clean || isset($seen[$clean['name']])) continue;
    $out[]=$clean; $seen[$clean['name']]=true;
  }
  usort($out,fn($a,$b)=>strcmp($a['name'],$b['name']));
  return $out;
}
function next_probe_port($customOuts,$outs,$state){
  $used=[10085=>true];
  foreach($customOuts as $o){ $p=intval($o['probe_port'] ?? 0); if($p>0) $used[$p]=true; }
  foreach($outs as $o){ $p=intval($o['port'] ?? 0); if($p>0) $used[$p]=true; }
  foreach(($state['ports'] ?? []) as $p){ $port=intval($p['port'] ?? 0); if($port>0) $used[$port]=true; }
  for($port=31000;$port<=31999;$port++){ if(empty($used[$port])) return $port; }
  return random_int(32000,39999);
}
function parse_vmess_import($link){
  $link=trim((string)$link);
  if($link==='') return [false,null,'请先粘贴 VMess 链接。'];
  if(stripos($link,'vmess://')===0) $link=substr($link,8);
  $payload=preg_replace('/\s+/','',$link);
  $payload=strtr($payload,'-_','+/');
  $payload.=str_repeat('=',(4-strlen($payload)%4)%4);
  $json=base64_decode($payload,true);
  if($json===false) return [false,null,'VMess Base64 解码失败。'];
  $obj=json_decode($json,true);
  if(!is_array($obj)) return [false,null,'VMess 内容不是有效 JSON。'];
  $item=[
    'name'=>trim((string)($obj['ps'] ?? '')),
    'protocol'=>'vmess',
    'address'=>trim((string)($obj['add'] ?? '')),
    'remote_port'=>intval($obj['port'] ?? 0),
    'id'=>trim((string)($obj['id'] ?? '')),
    'aid'=>intval($obj['aid'] ?? 0),
    'security'=>trim((string)($obj['scy'] ?? 'auto')) ?: 'auto',
    'network'=>trim((string)($obj['net'] ?? 'tcp')) ?: 'tcp',
    'header_type'=>trim((string)($obj['type'] ?? 'none')) ?: 'none',
    'host'=>trim((string)($obj['host'] ?? '')),
    'path'=>trim((string)($obj['path'] ?? '')),
    'tls'=>trim((string)($obj['tls'] ?? '')),
    'sni'=>trim((string)($obj['sni'] ?? '')),
    'alpn'=>trim((string)($obj['alpn'] ?? '')),
    'fp'=>trim((string)($obj['fp'] ?? '')),
    'insecure'=>trim((string)($obj['insecure'] ?? '0')),
  ];
  if($item['name']==='') $item['name']=$item['address'].':'.$item['remote_port'];
  $item['probe_port']=1;
  $clean=normalize_custom_outbound($item);
  if(!$clean) return [false,null,'VMess 缺少地址、端口或用户 ID。'];
  return [true,$clean,''];
}
function remove_outbound_references(&$state,$name){
  foreach(($state['smart_pools'] ?? []) as &$pool){
    $members=normalize_members($pool['members'] ?? []);
    $pool['members']=array_values(array_filter($members,fn($m)=>$m!==$name));
  }
  unset($pool);
  foreach(($state['ports'] ?? []) as &$port){
    foreach(($port['rules'] ?? []) as &$rule){
      if(($rule['outbound'] ?? '')===$name) $rule['outbound']='';
    }
    unset($rule);
  }
  unset($port);
}
function validate_ip_rule_input($text){
  $result=[];
  foreach(preg_split('/\r\n|\r|\n/',trim((string)$text)) as $line){
    $line=trim($line); if($line==='') continue;
    if(preg_match('/^IP-CIDR6?\s*,\s*([^,]+)(?:\s*,\s*no-resolve)?$/i',$line,$m)) $line=trim($m[1]);
    foreach(preg_split('/[,\s]+/',$line) as $item){
      if($item==='*' || preg_match('/^(?:ext-ip:[^\s,]+|geoip:[!A-Za-z0-9_.@-]+)$/',$item)){ $result[]=$item; continue; }
      $parts=explode('/',$item);
      $is4=filter_var($parts[0],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)!==false;
      $is6=filter_var($parts[0],FILTER_VALIDATE_IP,FILTER_FLAG_IPV6)!==false;
      if((!$is4 && !$is6) || count($parts)>2 || (isset($parts[1]) && (!ctype_digit($parts[1]) || intval($parts[1])>($is4?32:128))))
        throw new InvalidArgumentException('IP 匹配格式错误：'.$item.'。请填写 IP/CIDR、geoip:名称，或每行 IP-CIDR,网段。');
      $result[]=$item;
    }
  }
  return implode("\n",array_values(array_unique($result)));
}

function normalize_rule($rule){
  if(!is_array($rule)) $rule=[];
  $id=trim((string)($rule['id'] ?? ''));
  if($id==='') $id=new_rule_id();
  return ['id'=>$id,'name'=>strval($rule['name'] ?? '自定义规则'),'domains'=>strval($rule['domains'] ?? ''),'ips'=>strval($rule['ips'] ?? ''),'outbound'=>strval($rule['outbound'] ?? '')];
}
function find_rule_index($rules,$ruleId,$fallbackIdx=-1){
  if(!is_array($rules)) return -1;
  $ruleId=trim((string)$ruleId);
  if($ruleId!==''){ foreach($rules as $i=>$rule){ if(is_array($rule) && (string)($rule['id'] ?? '')===$ruleId) return intval($i); } return -1; }
  $fallbackIdx=intval($fallbackIdx);
  return ($fallbackIdx>=0 && isset($rules[$fallbackIdx])) ? $fallbackIdx : -1;
}
function normalize_state($state){
  if(!is_array($state)) $state=[];
  if(empty($state['ports']) || !is_array($state['ports'])) $state['ports']=[];
  foreach($state['ports'] as &$port){
    if(empty($port['rules']) || !is_array($port['rules'])) $port['rules']=[];
    $rules=[];
    foreach($port['rules'] as $rule){ $rules[]=normalize_rule($rule); }
    $port['rules']=$rules;
  }
  unset($port);
  $state['smart_pools']=normalize_smart_pools($state['smart_pools'] ?? []);
  return $state;
}
function normalize_export($export){
  if(!is_array($export)) $export=[];
  if(empty($export['default_address'])) $export['default_address']='127.0.0.1';
  if(empty($export['aliases']) || !is_array($export['aliases'])) $export['aliases']=[];
  return $export;
}
function fmt_time($ts){ $ts=intval($ts); return $ts>0 ? date('Y-m-d H:i:s',$ts) : '—'; }
function fmt_age($ts){
  $ts=intval($ts); if($ts<=0) return '—';
  $diff=max(0,time()-$ts);
  if($diff<60) return $diff.' 秒前';
  if($diff<3600) return floor($diff/60).' 分钟前';
  if($diff<86400) return floor($diff/3600).' 小时前';
  return floor($diff/86400).' 天前';
}
function fmt_duration($seconds){
  $seconds=max(0,intval($seconds));
  if($seconds<=0) return '—';
  $days=intdiv($seconds,86400); $seconds%=86400;
  $hours=intdiv($seconds,3600); $seconds%=3600;
  $minutes=intdiv($seconds,60); $secs=$seconds%60;
  $parts=[];
  if($days>0) $parts[]=$days.' 天';
  if($hours>0 || $days>0) $parts[]=$hours.' 小时';
  if($minutes>0 || $hours>0 || $days>0) $parts[]=$minutes.' 分钟';
  if(empty($parts)) $parts[]=$secs.' 秒';
  return implode(' ',array_slice($parts,0,3));
}
function bytes_text($bytes){
  $bytes=max(0,floatval($bytes));
  $units=['B','KB','MB','GB','TB']; $i=0;
  while($bytes>=1024 && $i<count($units)-1){ $bytes/=1024; $i++; }
  return ($i===0 ? intval($bytes) : number_format($bytes,2)).' '.$units[$i];
}
function status_label($s){ if($s==='healthy') return '调度中'; if($s==='warning') return '观察中'; if($s==='isolated') return '已剔除'; return '未知'; }
function status_class($s){ if($s==='healthy') return 'healthy'; if($s==='warning') return 'warning'; if($s==='isolated') return 'isolated'; return 'unknown'; }
function latency_text($node){
  if(isset($node['latency_ms']) && $node['latency_ms']!==null) return intval($node['latency_ms']).' ms';
  if(isset($node['latency']) && $node['latency']!==null) return intval(round(floatval($node['latency'])*1000)).' ms';
  return '—';
}
function tcp_latency_text($node){
  if(isset($node['tcp_latency_ms']) && $node['tcp_latency_ms']!==null) return intval($node['tcp_latency_ms']).' ms';
  if(isset($node['tcp_latency']) && $node['tcp_latency']!==null) return intval(round(floatval($node['tcp_latency'])*1000)).' ms';
  return '—';
}
function schedule_apply($reason=''){
  global $applyStatusFile;
  $reason=trim((string)$reason);
  save_json($applyStatusFile,['status'=>'queued','started_at'=>time(),'finished_at'=>0,'code'=>null,'reason'=>$reason,'output'=>'']);
  @chmod($applyStatusFile,0664);
  shell_exec('/usr/local/bin/ixr-apply-async '.escapeshellarg($reason).' >/dev/null 2>&1 &');
}
function discover_local_ips(){
  $ips=[];
  $out=@shell_exec('ip -o -4 addr show scope global 2>/dev/null');
  foreach(preg_split('/[
]+/', (string)$out) as $line){
    if(preg_match('/\sinet\s+([0-9.]+)\//',$line,$m)){
      $ip=$m[1];
      if(filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4) && !in_array($ip,$ips,true)) $ips[]=$ip;
    }
  }
  sort($ips,SORT_NATURAL);
  return $ips;
}
function local_ip_label($ip){ return 'Local IP '.$ip; }

function sync_outbounds(&$syncMsg){
  $syncMsg='IXR 出口、端口与 IX 线路统一由 Xray 配置生成器管理。';
}
function vmess_link($portConfig,$export){
  $port=(string)$portConfig['port'];
  $alias=$export['aliases'][$port] ?? ('IXR-'.$port);
  $address=$export['default_address'] ?? '127.0.0.1';
  $obj=['v'=>'2','ps'=>$alias,'add'=>$address,'port'=>$port,'id'=>$portConfig['uuid'],'aid'=>'0','scy'=>'auto','net'=>'tcp','type'=>'none','host'=>'','path'=>'','tls'=>''];
  return 'vmess://'.base64_encode(json_encode($obj,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
}
function section_url($section,$port=0,$params=[]){ $url='/admin.php?section='.rawurlencode($section); if($port) $url.='&port='.intval($port); foreach($params as $k=>$v){ if($v!=='' && $v!==null) $url.='&'.rawurlencode((string)$k).'='.rawurlencode((string)$v); } return $url; }
function redirect_back($port=0,$section='ports',$params=[]){
  header('Location: '.section_url($section,$port,$params));
  exit;
}
function set_flash($title,$body='',$kind='ok'){ $_SESSION['ixr_flash']=['title'=>$title,'body'=>$body,'kind'=>$kind]; }
function nav_active($current,$section){ return $current===$section ? 'active' : ''; }

$loginError='';
if(isset($_POST['login_act'])){
  try {
    if(($_POST['username'] ?? '')===$USER && ixr_verify_admin_password((string)($_POST['password'] ?? ''),$PASS)){
      session_regenerate_id(true); ixr_mark_admin_session($PASS); header('Location: /admin.php'); exit;
    }
    $loginError='用户名或密码不对';
  } catch(Throwable $error){ $loginError='后台认证配置不可用'; }
}
if(isset($_GET['logout'])){ $_SESSION=[]; session_destroy(); header('Location: /admin.php'); exit; }
if(!empty($_SESSION['ixr_login'])){
  try {
    if(!ixr_admin_session_valid($PASS)){ $_SESSION=[]; session_destroy(); $loginError='登录状态已失效，请重新登录'; }
  } catch(Throwable $error){ $_SESSION=[]; session_destroy(); $loginError='后台认证配置不可用'; }
}
if(empty($_SESSION['ixr_login'])){
?><!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>线路管理登录</title><style>body{font-family:system-ui,-apple-system,Segoe UI,Arial,"Microsoft YaHei",sans-serif;background:linear-gradient(135deg,#1f6feb,#7c3aed);min-height:100vh;margin:0;display:grid;place-items:center;color:#172033}.box{width:min(420px,92vw);background:white;border-radius:22px;padding:28px;box-shadow:0 24px 70px #11182755}h1{margin:0 0 22px}label{font-weight:700;font-size:14px}input{width:100%;box-sizing:border-box;border:1px solid #d8deea;border-radius:12px;padding:12px;margin:7px 0 15px;font-size:15px}.btn{width:100%;border:0;border-radius:12px;padding:12px;font-weight:800;background:#1f6feb;color:white;cursor:pointer}.err{background:#fee2e2;color:#991b1b;border-radius:10px;padding:10px;margin-bottom:12px}.user-entry{display:block;text-align:center;margin-top:14px;color:#2563eb;text-decoration:none;font-weight:800}</style></head><body><form class="box" method="post"><h1>线路管理</h1><?php if($loginError): ?><div class="err"><?=h($loginError)?></div><?php endif; ?><input type="hidden" name="login_act" value="1"><label>用户名</label><input name="username" autocomplete="username" autofocus><label>密码</label><input name="password" type="password" autocomplete="current-password"><button class="btn">登录</button><a class="user-entry" href="/">线路服务中心</a></form><script id="ixr-submit-guard">document.addEventListener('submit',function(e){var f=e.target;if(!f||!f.querySelector)return;if(f.dataset.submitting==='1'){e.preventDefault();return false;}f.dataset.submitting='1';setTimeout(function(){var btns=f.querySelectorAll('button[type=submit],button:not([type])');btns.forEach(function(b){b.disabled=true;b.style.opacity='.65';});},0);},true);</script></body></html><?php exit; }

$section=$_GET['section'] ?? 'dashboard';
if(isset($_GET['port'])) $section='ports';
$section=$section==='outbounds' ? 'ix-admin' : $section;
$allowed=['dashboard','ports','usage','pools','outbounds','account','ix-admin','add-port'];
if(!in_array($section,$allowed,true)) $section='dashboard';
$adminCsrf=ixr_csrf_token();

$syncMsg='';
sync_outbounds($syncMsg);
$rawState=load_json($stateFile,['ports'=>[]]);
$state=normalize_state(load_json($stateFile,['ports'=>[]]));
$missingRuleIds=false; foreach(($rawState['ports'] ?? []) as $rp){ foreach(($rp['rules'] ?? []) as $rr){ if(empty($rr['id'])) $missingRuleIds=true; } }
if($missingRuleIds) save_state($state);
$outs=normalize_custom_outbounds(load_json($outFile,[]));
$localIps=discover_local_ips();
$customOuts=$outs;
$smartPools=$state['smart_pools'] ?? normalize_smart_pools([]);
$export=normalize_export(load_json($exportFile,[]));

if($_SERVER['REQUEST_METHOD']==='POST' && empty($_POST['login_act'])){
  $act=$_POST['act'] ?? '';
  $targetPort=intval($_POST['port'] ?? 0);
  if(in_array($act,['add_rule','save_rule'],true)){
    try { $_POST['ips']=validate_ip_rule_input($_POST['ips'] ?? ''); }
    catch(Throwable $error){ set_flash('规则未保存',$error->getMessage(),'warn'); redirect_back($targetPort,'ports'); }
  }

  $needsApply=false; $applyPrefix=''; $redirectSection=$_POST['section'] ?? 'ports'; $redirectParams=[];
  if(!in_array($redirectSection,$allowed,true)) $redirectSection='ports';
  if($act==='change_admin_password'){
    try {
      if(!ixr_verify_csrf((string)($_POST['csrf'] ?? ''))) throw new RuntimeException('页面已过期，请刷新后重试');
      ixr_change_admin_password((string)($_POST['current_password'] ?? ''),(string)($_POST['new_password'] ?? ''),(string)($_POST['confirm_password'] ?? ''),$PASS);
      session_regenerate_id(true); ixr_mark_admin_session($PASS);
      try { ixr_audit(ixr_user_db(),$USER,'admin_password_changed','admin',null); } catch(Throwable $ignored) {}
      set_flash('后台密码已修改');
    } catch(Throwable $error){ set_flash('后台密码修改失败',$error->getMessage(),'warn'); }
    redirect_back(0,'account');
  }
  if(in_array($act,['delete_rule','delete_port','delete_pool','delete_custom_outbound'],true)){
    $deleteKey=$_POST['rule_id'] ?? ($_POST['pool_id'] ?? ($_POST['custom_outbound_name'] ?? ($_POST['idx'] ?? '')));
    $deleteSig=hash('sha256',$act.'|'.$targetPort.'|'.$deleteKey.'|'.$redirectSection);
    $lastSig=$_SESSION['ixr_last_delete_sig'] ?? '';
    $lastTime=intval($_SESSION['ixr_last_delete_time'] ?? 0);
    if($lastSig===$deleteSig && time()-$lastTime<10){ set_flash('重复删除已忽略','检测到同一删除请求短时间内重复提交，已自动拦截第二次操作。','warn'); redirect_back($targetPort,$redirectSection); }
    $_SESSION['ixr_last_delete_sig']=$deleteSig; $_SESSION['ixr_last_delete_time']=time();
  }

  if($act==='save_export_global'){
    $export['default_address']=trim($_POST['default_address'] ?? '127.0.0.1') ?: '127.0.0.1';
    save_export($export); set_flash('连接地址已保存'); redirect_back($targetPort,'ports');
  }
  if($act==='save_export_port'){
    $port=(string)$targetPort; $alias=trim($_POST['alias'] ?? ''); if($alias==='') $alias='IXR-'.$port;
    $export['aliases'][$port]=$alias; save_export($export);
    try { ixr_sync_port_labels(ixr_user_db(), intval($port)); } catch(Throwable $error) {}
    set_flash('端口 '.$port.' 的导出别名已保存'); redirect_back($targetPort,'ports');
  }
  if($act==='import_vmess'){
    [$ok,$item,$err]=parse_vmess_import($_POST['vmess_link'] ?? '');
    if(!$ok){ set_flash('VMess 导入失败',$err,'warn'); redirect_back($targetPort,'outbounds'); }
    $overrideName=trim((string)($_POST['name'] ?? '')); if($overrideName!=='') $item['name']=$overrideName;
    $customNames=array_column($customOuts,'name');
    foreach($outs as $out){ if(($out['name'] ?? '')===$item['name'] && !in_array($item['name'],$customNames,true)){ set_flash('VMess 导入失败','这个出口名称已经存在，请换一个别名。','warn'); redirect_back($targetPort,'outbounds'); } }
    $existingProbe=0; foreach($customOuts as $old){ if(($old['name'] ?? '')===$item['name']) $existingProbe=intval($old['probe_port'] ?? 0); }
    $inputProbe=intval($_POST['probe_port'] ?? 0);
    $item['probe_port']=$inputProbe>0 ? $inputProbe : ($existingProbe>0 ? $existingProbe : next_probe_port($customOuts,$outs,$state));
    $item=normalize_custom_outbound($item);
    if(!$item){ set_flash('VMess 瀵煎叆澶辫触','请确认 VMess 内容和本地探测端口有效。','warn'); redirect_back($targetPort,'outbounds'); }
    $replaced=false;
    foreach($customOuts as &$old){ if(($old['name'] ?? '')===$item['name']){ $old=$item; $replaced=true; } }
    unset($old);
    if(!$replaced) $customOuts[]=$item;
    save_custom_outbounds(normalize_custom_outbounds($customOuts));
    if(stripos($item['name'],'DN42')!==false){ foreach($state['smart_pools'] as &$pool){ if(($pool['id'] ?? '')==='dn42' || ($pool['name'] ?? '')==='DN42智能自动'){ $members=normalize_members($pool['members'] ?? []); if(!in_array($item['name'],$members,true)) $members[]=$item['name']; $pool['members']=$members; if(trim((string)($pool['keyword'] ?? ''))==='') $pool['keyword']='DN42'; } } unset($pool); }
    $applyPrefix=($replaced?'已更新出口：':'已导入出口：').$item['name'].'。'; $needsApply=true; $redirectSection='outbounds'; $redirectParams=['edit_outbound'=>$item['name']];
  }
  if($act==='save_custom_outbound'){
    $oldName=trim((string)($_POST['custom_outbound_name'] ?? ''));
    $existingProbe=0; foreach($customOuts as $old){ if(($old['name'] ?? '')===$oldName) $existingProbe=intval($old['probe_port'] ?? $old['port'] ?? 0); }
    $inputProbe=intval($_POST['probe_port'] ?? 0);
    $probePort=$inputProbe>0 ? $inputProbe : ($existingProbe>0 ? $existingProbe : next_probe_port($customOuts,$outs,$state));
    $item=normalize_custom_outbound([
      'name'=>trim((string)($_POST['name'] ?? '')),
      'protocol'=>'vmess',
      'address'=>trim((string)($_POST['address'] ?? '')),
      'remote_port'=>intval($_POST['remote_port'] ?? 0),
      'id'=>trim((string)($_POST['id'] ?? '')),
      'aid'=>intval($_POST['aid'] ?? 0),
      'security'=>trim((string)($_POST['security'] ?? 'auto')),
      'network'=>trim((string)($_POST['network'] ?? 'tcp')),
      'header_type'=>trim((string)($_POST['header_type'] ?? 'none')),
      'host'=>trim((string)($_POST['host'] ?? '')),
      'path'=>trim((string)($_POST['path'] ?? '')),
      'tls'=>trim((string)($_POST['tls'] ?? '')),
      'sni'=>trim((string)($_POST['sni'] ?? '')),
      'alpn'=>trim((string)($_POST['alpn'] ?? '')),
      'fp'=>trim((string)($_POST['fp'] ?? '')),
      'insecure'=>trim((string)($_POST['insecure'] ?? '0')),
      'probe_port'=>$probePort,
    ]);
    if(!$item){ set_flash('保存出口失败','请确认名称、地址、远端端口、用户 ID、本地探测端口都已填写。','warn'); redirect_back($targetPort,'outbounds'); }
    if($oldName!=='' && $oldName!==$item['name'] && isset(ixr_ix_route_catalog()[$oldName])){
      set_flash('IX 线路不能在这里改名','请到“IX 出口管理”中修改线路名称，避免线路目录和用户授权失去关联。','warn'); redirect_back($targetPort,'outbounds');
    }
    $customNames=array_column($customOuts,'name');
    foreach($outs as $out){ if(($out['name'] ?? '')===$item['name'] && !in_array($item['name'],$customNames,true)){ set_flash('保存出口失败','这个出口名称已经存在，请换一个名称。','warn'); redirect_back($targetPort,'outbounds'); } }
    foreach($customOuts as $old){ if(($old['name'] ?? '')===$item['name'] && $oldName!==$item['name']){ set_flash('保存出口失败','这个自定义出口名称已经存在。','warn'); redirect_back($targetPort,'outbounds'); } }
    $saved=false;
    foreach($customOuts as &$old){ if(($old['name'] ?? '')===$oldName){ $old=$item; $saved=true; } }
    unset($old);
    if(!$saved) $customOuts[]=$item;
    if($oldName!=='' && $oldName!==$item['name']){
      foreach($state['smart_pools'] as &$pool){ $members=normalize_members($pool['members'] ?? []); foreach($members as &$member){ if($member===$oldName) $member=$item['name']; } unset($member); $pool['members']=array_values(array_unique($members)); } unset($pool);
      foreach($state['ports'] as &$portCfg){ foreach(($portCfg['rules'] ?? []) as &$rule){ if(($rule['outbound'] ?? '')===$oldName) $rule['outbound']=$item['name']; } unset($rule); } unset($portCfg);
    }
    if(stripos($item['name'],'DN42')!==false){ foreach($state['smart_pools'] as &$pool){ if(($pool['id'] ?? '')==='dn42' || ($pool['name'] ?? '')==='DN42智能自动'){ $members=normalize_members($pool['members'] ?? []); if(!in_array($item['name'],$members,true)) $members[]=$item['name']; $pool['members']=$members; } } unset($pool); }
    save_custom_outbounds(normalize_custom_outbounds($customOuts));
    $applyPrefix='出口已保存：'.$item['name'].'。'; $needsApply=true; $redirectSection='outbounds'; $redirectParams=['edit_outbound'=>$item['name']];
  }
  if($act==='delete_custom_outbound'){
    $name=trim((string)($_POST['custom_outbound_name'] ?? ''));
    if($name===''){ set_flash('删除出口失败','出口名称为空，请刷新页面后重试。','warn'); redirect_back($targetPort,'outbounds'); }
    try {
      $result=ixr_admin_xray_call('delete_node',['tag'=>$name]);
      if(($result['success'] ?? false)!==true) throw new RuntimeException((string)($result['error'] ?? '统一删除后端执行失败'));
      set_flash('出口已删除',(string)($result['message'] ?? ('已删除出口：'.$name.'。')));
    } catch(Throwable $error){
      set_flash('删除出口失败',$error->getMessage(),'warn');
    }
    redirect_back($targetPort,'outbounds');
  }
  if($act==='save_pool'){
    $poolId=trim((string)($_POST['pool_id'] ?? '')); $saved=false;
    foreach($state['smart_pools'] as &$pool){
      if(($pool['id'] ?? '')===$poolId){
        $pool['members']=normalize_members($_POST['members'] ?? []);
        $pool['keyword']=trim((string)($_POST['keyword'] ?? ''));
        $applyPrefix='自动池 '.$pool['name'].' 已保存。';
        $saved=true;
      }
    }
    unset($pool);
    if($saved){ $needsApply=true; $redirectSection='pools'; }
    else { set_flash('没有找到要保存的自动池','请刷新页面后再操作。','warn'); redirect_back($targetPort,'pools'); }
  }
  if($act==='add_pool'){
    $name=trim((string)($_POST['name'] ?? '')); $exists=false;
    if($name===''){ set_flash('自动池添加失败','请填写一个容易识别的池名称。','warn'); redirect_back($targetPort,'pools'); }
    foreach($state['smart_pools'] as $pool){ if(($pool['name'] ?? '')===$name) $exists=true; }
    foreach($outs as $out){ if(($out['name'] ?? '')===$name) $exists=true; }
    if($exists){ set_flash('自动池添加失败','这个名称已经被自动池或出口节点使用，请换一个。','warn'); redirect_back($targetPort,'pools'); }
    $state['smart_pools'][]=['id'=>new_pool_id($name),'name'=>$name,'members'=>normalize_members($_POST['members'] ?? []),'keyword'=>trim((string)($_POST['keyword'] ?? '')),'builtin'=>false];
    $applyPrefix='已添加自动池：'.$name.'。'; $needsApply=true; $redirectSection='pools';
  }
  if($act==='delete_pool'){
    $poolId=trim((string)($_POST['pool_id'] ?? '')); $poolName=''; $builtin=false;
    foreach($state['smart_pools'] as $pool){ if(($pool['id'] ?? '')===$poolId){ $poolName=$pool['name'] ?? ''; $builtin=!empty($pool['builtin']); } }
    if($poolName===''){ set_flash('没有找到要删除的自动池','请刷新页面后再操作。','warn'); redirect_back($targetPort,'pools'); }
    if($builtin){ set_flash('内置自动池不能删除','Google 和 DN42 内置池可以编辑成员，但不建议删除。','warn'); redirect_back($targetPort,'pools'); }
    $used=false; foreach($state['ports'] as $p){ foreach(($p['rules'] ?? []) as $rule){ if(($rule['outbound'] ?? '')===$poolName) $used=true; } }
    if($used){ set_flash('自动池正在使用中','先把端口规则里使用这个池的规则改到其他出口，再删除。','warn'); redirect_back($targetPort,'pools'); }
    $state['smart_pools']=array_values(array_filter($state['smart_pools'],fn($pool)=>($pool['id'] ?? '')!==$poolId));
    $applyPrefix='已删除自动池：'.$poolName.'。'; $needsApply=true; $redirectSection='pools';
  }
  if($act==='add_port'){
    $port=max(1,min(65535,intval($_POST['port'] ?? 0))); $exists=false; foreach($state['ports'] as $p){ if(intval($p['port'])===$port) $exists=true; }
    if($port && !$exists){ $state['ports'][]=['port'=>$port,'protocol'=>'vmess','uuid'=>new_uuid(),'email'=>"ixr-$port@example.com",'default'=>'auto-fast','rules'=>[]]; $export['aliases'][(string)$port]='IXR-'.$port; save_export($export); $targetPort=$port; $applyPrefix='已添加端口 '.$port.'。'; $needsApply=true; }
    else{ set_flash('端口添加失败','端口为空或已经存在。','warn'); redirect_back($targetPort,'add-port'); }
  }
  if($act==='delete_port'){
    $deleted=false; $state['ports']=array_values(array_filter($state['ports'],function($p) use ($targetPort,&$deleted){ if(intval($p['port'])===$targetPort){ $deleted=true; return false; } return true; }));
    unset($export['aliases'][(string)$targetPort]); save_export($export); $targetPort=count($state['ports']) ? intval($state['ports'][0]['port']) : 0; $applyPrefix=$deleted?'已删除端口。':'没有找到要删除的端口。'; $needsApply=true;
  }
  if($act==='save_port'){
    foreach($state['ports'] as &$p){ if(intval($p['port'])===$targetPort){ $p['uuid']=trim($_POST['uuid'] ?? $p['uuid']); $p['email']=trim($_POST['email'] ?? $p['email']); $applyPrefix='端口 '.$targetPort.' 设置已保存。'; }} unset($p); $needsApply=true;
  }
  if($act==='add_rule'){
    foreach($state['ports'] as &$p){ if(intval($p['port'])===$targetPort){ $name=trim($_POST['name'] ?? '新规则') ?: '新规则'; $p['rules'][]=['id'=>new_rule_id(),'name'=>$name,'domains'=>trim($_POST['domains'] ?? ''),'ips'=>trim($_POST['ips'] ?? ''),'outbound'=>trim($_POST['outbound'] ?? '')]; $applyPrefix='已添加规则：'.$name.'。'; }} unset($p); $needsApply=true;
  }
  if($act==='save_rule'){
    $ruleId=trim($_POST['rule_id'] ?? ''); $idx=intval($_POST['idx'] ?? -1); $saved=false;
    foreach($state['ports'] as &$p){ if(intval($p['port'])===$targetPort){ $ruleIdx=find_rule_index($p['rules'] ?? [],$ruleId,$ruleId===''?$idx:-1); if($ruleIdx>=0 && isset($p['rules'][$ruleIdx])){ $name=trim($_POST['name'] ?? '规则') ?: '规则'; $oldId=$p['rules'][$ruleIdx]['id'] ?? ($ruleId ?: new_rule_id()); $p['rules'][$ruleIdx]=['id'=>$oldId,'name'=>$name,'domains'=>trim($_POST['domains'] ?? ''),'ips'=>trim($_POST['ips'] ?? ''),'outbound'=>trim($_POST['outbound'] ?? '')]; $applyPrefix='规则已保存：'.$name.'。'; $saved=true; } }} unset($p);
    if($saved){ $needsApply=true; } else { set_flash('没有找到要保存的规则','这条规则可能已经被删除，或页面已经过期；请刷新后再操作。','warn'); redirect_back($targetPort,$redirectSection); }
  }
  if($act==='delete_rule'){
    $ruleId=trim($_POST['rule_id'] ?? ''); $idx=intval($_POST['idx'] ?? -1); $deletedName='';
    foreach($state['ports'] as &$p){ if(intval($p['port'])===$targetPort){ $ruleIdx=find_rule_index($p['rules'] ?? [],$ruleId,$ruleId===''?$idx:-1); if($ruleIdx>=0 && isset($p['rules'][$ruleIdx])){ $deletedName=$p['rules'][$ruleIdx]['name'] ?? ('第 '.($ruleIdx+1).' 条规则'); array_splice($p['rules'],$ruleIdx,1); } }} unset($p);
    if($deletedName){ $applyPrefix='已删除规则：'.$deletedName.'。'; $needsApply=true; }
    else { set_flash('重复删除已忽略','这条规则已经不存在，没有继续删除其他规则。','warn'); redirect_back($targetPort,$redirectSection); }
  }
  if($needsApply){
    usort($state['ports'],fn($a,$b)=>intval($a['port'])<=>intval($b['port'])); save_state($state);
    schedule_apply($applyPrefix ?: '配置变更'); set_flash($applyPrefix ?: '配置已保存','已保存，Xray 正在后台应用；如果你正好在使用这个端口，最多断开几秒后会自动恢复。'); redirect_back($targetPort,$redirectSection,$redirectParams);
  }
}

$state=normalize_state(load_json($stateFile,['ports'=>[]]));
$outs=normalize_custom_outbounds(load_json($outFile,[]));
$customOuts=$outs;
$export=normalize_export(load_json($exportFile,[]));
$health=load_json($healthFile,[]);
$usage=load_json($usageFile,['available'=>false,'nodes'=>[],'total_bytes'=>0]);
$applyStatus=load_json($applyStatusFile,[]);
$healthNodes=(isset($health['nodes']) && is_array($health['nodes'])) ? $health['nodes'] : [];
$outHealth=[];
foreach($outs as $o){ $name=(string)($o['name'] ?? ''); $node=(isset($healthNodes[$name]) && is_array($healthNodes[$name])) ? $healthNodes[$name] : []; $status=$node['status'] ?? 'unknown'; $outHealth[]=['name'=>$name,'port'=>$o['port'] ?? '', 'node'=>$node, 'status'=>$status]; }
usort($outHealth,function($a,$b){ $rank=['healthy'=>0,'warning'=>1,'unknown'=>2,'isolated'=>3]; $ra=$rank[$a['status']] ?? 2; $rb=$rank[$b['status']] ?? 2; if($ra!==$rb) return $ra<=>$rb; return strcmp($a['name'],$b['name']); });
$healthTotal=count($outHealth); $healthActive=0; $healthWarning=0; $healthOffline=0;
foreach($outHealth as $item){ if($item['status']==='isolated') $healthOffline++; else $healthActive++; if($item['status']==='warning') $healthWarning++; }
$usageNodes=(isset($usage['nodes']) && is_array($usage['nodes'])) ? $usage['nodes'] : [];
$usagePorts=(isset($usage['ports']) && is_array($usage['ports'])) ? $usage['ports'] : [];
$usagePortGroups=(isset($usage['outbounds_by_port']) && is_array($usage['outbounds_by_port'])) ? $usage['outbounds_by_port'] : [];
$topUsage=$usageNodes[0] ?? null;
$topPortUsage=null; foreach($usagePorts as $up){ if(!$topPortUsage || intval($up['total'] ?? 0)>intval($topPortUsage['total'] ?? 0)) $topPortUsage=$up; }
$activeUsagePort=isset($_GET['usage_port']) ? intval($_GET['usage_port']) : 0;
$activeOutboundUsageTitle='全部端口'; $activeOutboundUsageNodes=$usageNodes; $activeOutboundUsageTotal=$usage['total_bytes'] ?? 0;
foreach($usagePortGroups as $ug){ if(intval($ug['port'] ?? 0)===$activeUsagePort){ $activeOutboundUsageTitle='端口 '.intval($ug['port']); $activeOutboundUsageNodes=(isset($ug['nodes']) && is_array($ug['nodes'])) ? $ug['nodes'] : []; $activeOutboundUsageTotal=$ug['total_bytes'] ?? 0; }}
$usageResetAt=intval($usage['stats_since_at'] ?? ($usage['reset_at'] ?? 0));
$usageUpdatedAt=intval($usage['updated_at'] ?? 0);
$usagePeriodEnd=$usageUpdatedAt>0 ? $usageUpdatedAt : time();
$usagePeriodSeconds=($usageResetAt>0 && $usagePeriodEnd>=$usageResetAt) ? ($usagePeriodEnd-$usageResetAt) : 0;
$usagePeriodText=fmt_duration($usagePeriodSeconds);
$usagePeriodRange=$usageResetAt>0 ? ('自 '.fmt_time($usageResetAt).' 起') : '未记录开始时间';
$activePort = isset($_GET['port']) ? intval($_GET['port']) : (count($state['ports']) ? intval($state['ports'][0]['port']) : 0);
$activePortConfig=null; foreach($state['ports'] as $p){ if(intval($p['port'])===$activePort) $activePortConfig=$p; }
if(!$activePortConfig && count($state['ports'])){ $activePortConfig=$state['ports'][0]; $activePort=intval($activePortConfig['port']); }
$flash=$_SESSION['ixr_flash'] ?? null; unset($_SESSION['ixr_flash']);
?><!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>线路管理</title><style>
:root{--bg:#f4f7fb;--card:#fff;--text:#172033;--muted:#64748b;--line:#e5eaf3;--blue:#2563eb;--green:#16a34a;--red:#ef4444;--amber:#f59e0b;--shadow:0 12px 30px #1f293714}*{box-sizing:border-box}body{font-family:system-ui,-apple-system,Segoe UI,Arial,"Microsoft YaHei",sans-serif;background:var(--bg);color:var(--text);margin:0}.shell{min-height:100vh}.side{pointer-events:auto;position:fixed;left:0;top:0;bottom:0;width:clamp(218px,15vw,280px);z-index:2147483000;height:100vh;background:#0f172a;color:white;padding:22px 16px;display:flex;flex-direction:column;gap:18px}.brand{font-size:22px;font-weight:900}.brand small{display:block;font-size:12px;color:#94a3b8;margin-top:4px}.nav{display:grid;gap:8px}.nav form{margin:0;position:relative;z-index:2147483001}.nav a,.nav button{pointer-events:auto;position:relative;z-index:2147483002;display:block;width:100%;text-align:left;color:#dbeafe;text-decoration:none;border:0;border-radius:12px;padding:11px 12px;font:inherit;font-weight:800;background:transparent;cursor:pointer}.nav a:hover,.nav a.active,.nav button:hover,.nav button.active{background:#1e293b;color:white}.side-metrics{margin-top:auto;display:grid;gap:8px}.side-pill{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:10px 12px;font-size:13px}.side-pill b{float:right}.logout{color:#bfdbfe;text-decoration:none;font-size:13px}.main{padding:26px;width:calc(100% - clamp(218px,15vw,280px));max-width:none;margin-left:clamp(218px,15vw,280px)}.hero{background:linear-gradient(135deg,#2563eb,#7c3aed);color:white;border-radius:22px;padding:22px 24px;box-shadow:0 16px 36px #1f293722}.hero h1{margin:0 0 6px}.hero p{margin:0;color:#e0e7ff}.section{margin-top:18px}.section-head{display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap}.card{background:var(--card);border:1px solid #edf1f7;border-radius:18px;padding:18px;margin:14px 0;box-shadow:var(--shadow)}.split{display:grid;grid-template-columns:minmax(420px,1fr) minmax(330px,420px);gap:16px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}label{font-weight:800;font-size:13px;color:#334155}input,textarea,select{width:100%;border:1px solid #d8deea;border-radius:12px;padding:10px 11px;margin:6px 0 11px;font-size:14px;background:white}textarea{min-height:76px;resize:vertical}.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:0;border-radius:11px;padding:9px 13px;font-weight:900;cursor:pointer;background:var(--blue);color:white;white-space:nowrap;text-decoration:none;line-height:1.2}.btn:hover{filter:brightness(.97)}.btn.edit{background:linear-gradient(135deg,#2563eb,#7c3aed);box-shadow:0 8px 18px #2563eb28}.btn.edit:hover{filter:none;transform:translateY(-1px);box-shadow:0 10px 22px #2563eb35}.btn.red{background:var(--red)}.btn.green{background:var(--green)}.btn.ghost{background:#eef2ff;color:#3730a3}.hint{color:var(--muted);font-size:13px}.msg{white-space:pre-wrap;background:#0f172a;color:#d1fae5;border-radius:12px;padding:12px;overflow:auto;max-height:260px}.flash{border-left:6px solid var(--green)}.flash.warn{border-left-color:var(--amber)}.flash.err{border-left-color:var(--red)}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px}.metric{background:#f8fafc;border:1px solid #e2e8f0;border-radius:14px;padding:13px}.metric span{display:block;color:#64748b;font-size:12px}.metric b{font-size:24px}.metric.good b{color:#047857}.metric.warn b{color:#b45309}.metric.bad b{color:#b91c1c}.health-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px}.node-card{border:1px solid var(--line);border-radius:15px;padding:13px;background:#fbfdff}.node-card.healthy{border-color:#bbf7d0;background:#f0fdf4}.node-card.warning{border-color:#fde68a;background:#fffbeb}.node-card.isolated{border-color:#fecaca;background:#fff1f2}.node-title,.rule-head{display:flex;justify-content:space-between;gap:8px;align-items:center;flex-wrap:wrap}.status-badge{border-radius:99px;padding:4px 9px;font-size:12px;font-weight:900}.status-badge.healthy{background:#16a34a;color:white}.status-badge.warning{background:#f59e0b;color:white}.status-badge.isolated{background:#ef4444;color:white}.status-badge.unknown{background:#64748b;color:white}.node-row{display:flex;justify-content:space-between;gap:10px;border-top:1px dashed #dbe3ef;padding-top:7px;margin-top:7px;font-size:13px}.node-row span{color:#64748b}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 16px}.tab{display:inline-flex;align-items:center;gap:7px;text-decoration:none;color:#334155;background:#e8eef8;border:1px solid #d7deeb;border-radius:13px;padding:10px 14px;font-weight:900}.tab.active{background:var(--blue);color:white;border-color:var(--blue);box-shadow:0 8px 18px #2563eb33}.tab small{font-weight:800;opacity:.75}.rule{border:1px solid var(--line);border-radius:15px;padding:14px;margin:12px 0;background:#fbfdff}.rule-actions{display:flex;gap:8px}.vmess-box{font-family:Consolas,monospace;min-height:92px}.copy-row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.copy-ok{color:#16a34a;font-weight:900}.table-wrap{overflow:auto}.usage-table{width:100%;border-collapse:collapse;min-width:760px}.usage-table th,.usage-table td{padding:11px 10px;border-bottom:1px solid var(--line);text-align:left}.usage-table th{color:#475569;font-size:13px}.bar{height:9px;background:#e2e8f0;border-radius:99px;overflow:hidden;min-width:140px}.bar i{display:block;height:100%;background:linear-gradient(90deg,#2563eb,#7c3aed);border-radius:99px}.mini-list{display:flex;gap:6px;flex-wrap:wrap}.mini-pill{background:#eef2ff;color:#3730a3;border-radius:999px;padding:5px 9px;font-size:12px;font-weight:800}.embed-frame{width:100%;min-height:calc(100vh - 150px);border:0;border-radius:18px;background:white;box-shadow:var(--shadow)}@media(max-width:980px){.shell{display:block}.side{position:relative;width:auto;height:auto}.side-metrics{margin-top:0}.main{padding:16px;width:100%;margin-left:0}.split,.grid{grid-template-columns:1fr}.summary{grid-template-columns:repeat(2,1fr)}}
.embed-frame{height:calc(100vh - 52px);min-height:720px;background:transparent;box-shadow:none}
.nav{gap:16px;align-content:start;overflow-y:auto;padding-right:2px}.nav-group{display:grid;gap:6px}.nav-parent{padding:0 10px;color:#64748b;font-size:11px;font-weight:900;letter-spacing:.12em}.nav-children{display:grid;gap:4px;padding-left:8px;border-left:1px solid #334155}.nav-children a,.nav-children button{padding:9px 10px;font-size:14px}.side-actions{display:grid;grid-template-columns:1fr 1fr;gap:8px}.side-action{display:flex;align-items:center;justify-content:center;min-width:0;border:1px solid #334155;border-radius:10px;padding:9px 8px;color:#dbeafe;text-decoration:none;font-size:12px;font-weight:900;background:#1e293b}.side-action:hover,.side-action.active{border-color:#60a5fa;background:#1d4ed8;color:#fff}.side-action.logout{color:#fecaca}.side-action.logout:hover{border-color:#f87171;background:#991b1b}.side-metrics{gap:9px}
</style></head>
<body>
<div class="shell">
<aside class="side">
<div class="brand">IXR</div>
<nav class="nav">
<section class="nav-group"><div class="nav-parent">运行概览</div><div class="nav-children"><a class="<?=nav_active($section,'dashboard')?>" href="/admin.php?section=dashboard">线路总览</a><a class="<?=nav_active($section,'usage')?>" href="/admin.php?section=usage">流量统计</a></div></section>
<section class="nav-group"><div class="nav-parent">线路配置</div><div class="nav-children"><a class="<?=nav_active($section,'ix-admin')?>" href="/admin.php?section=ix-admin">统一出口管理</a><a class="<?=nav_active($section,'ports')?>" href="/admin.php?section=ports&port=<?=h($activePort)?>">IXR 端口路由</a><a class="<?=nav_active($section,'pools')?>" href="/admin.php?section=pools">IXR 自动出口池</a><a class="<?=nav_active($section,'add-port')?>" href="/admin.php?section=add-port">新增 IXR 端口</a></div></section>
<section class="nav-group"><div class="nav-parent">用户管理</div><div class="nav-children"><a href="/users-admin.php">用户与配额</a></div></section>
<section class="nav-group"><div class="nav-parent">访问入口</div><div class="nav-children"><a href="/" target="_blank" rel="noopener">线路服务中心</a></div></section>
</nav>
<div class="side-metrics">
<div class="side-pill">参与调度 <b><?=h($healthActive)?></b></div>
<div class="side-pill">已剔除 <b><?=h($healthOffline)?></b></div>
<div class="side-pill">总使用量 <b><?=h(bytes_text($usage['total_bytes'] ?? 0))?></b></div>
<?php if($topUsage): ?><div class="side-pill">最常用 <b><?=h($topUsage['name'])?></b></div><?php endif; ?>
<div class="side-actions"><a class="side-action <?=nav_active($section,'account')?>" href="/admin.php?section=account">修改密码</a><a class="side-action logout" href="/admin.php?logout=1">退出登录</a></div>
</div>
</aside>
<main class="main">
<?php if($flash): ?><div class="card flash <?=h($flash['kind'] ?? 'ok')?>"><div class="section-head"><b><?=h($flash['title'] ?? '已完成')?></b></div><?php if(!empty($flash['body'])): ?><div class="msg"><?=h($flash['body'])?></div><?php endif; ?></div><?php endif; ?>
<?php if(!empty($applyStatus['status']) && (($applyStatus['status']==='queued' || $applyStatus['status']==='running') || time()-intval($applyStatus['finished_at'] ?? 0)<120)): $applyKind=($applyStatus['status']==='failed')?'err':(($applyStatus['status']==='queued'||$applyStatus['status']==='running')?'warn':'ok'); ?><div class="card flash <?=h($applyKind)?>"><div class="section-head"><b>后台应用状态：<?=h($applyStatus['status'])?></b><span class="hint"><?=h(fmt_time($applyStatus['finished_at'] ?? $applyStatus['started_at'] ?? 0))?></span></div><p class="hint"><?=h($applyStatus['reason'] ?? '配置变更')?>；页面已先返回，Xray 重启在后台完成。</p><?php if(!empty($applyStatus['output']) && $applyStatus['status']==='failed'): ?><div class="msg"><?=h($applyStatus['output'])?></div><?php endif; ?></div><?php endif; ?>
<?php if($section==='dashboard'): ?>
<section class="section"><div class="section-head"><h2>线路总览</h2><span class="hint">健康检测：<?=h(fmt_time($health['updated_at'] ?? 0))?>，<?=h(fmt_age($health['updated_at'] ?? 0))?></span></div><div class="summary"><div class="metric"><span>总出口</span><b><?=h($healthTotal)?></b></div><div class="metric good"><span>参与调度</span><b><?=h($healthActive)?></b></div><div class="metric warn"><span>观察中</span><b><?=h($healthWarning)?></b></div><div class="metric bad"><span>已剔除</span><b><?=h($healthOffline)?></b></div><div class="metric"><span>统计总量</span><b><?=h(bytes_text($usage['total_bytes'] ?? 0))?></b></div></div><div class="card"><div class="section-head"><h3>出口状态</h3><a class="btn ghost" href="<?=h(section_url('usage'))?>">查看流量统计</a></div><div class="health-grid"><?php foreach($outHealth as $item): $node=$item['node']; $status=$item['status']; $isActive=$status!=='isolated'; ?><div class="node-card <?=h(status_class($status))?>"><div class="node-title"><strong><?=h($item['name'])?></strong><span class="status-badge <?=h(status_class($status))?>"><?=h(status_label($status))?></span></div><div class="node-row"><span>调度池</span><b><?=$isActive?'参与 auto-fast':'暂时剔除'?></b></div><div class="node-row"><span>出口端口</span><b>127.0.0.1:<?=h($item['port'])?></b></div><div class="node-row"><span>TCP连接延迟</span><b><?=h(tcp_latency_text($node))?></b></div><div class="node-row"><span>实测访问延迟</span><b><?=h(latency_text($node))?></b></div><div class="node-row"><span>最近检测</span><b><?=h(fmt_age($node['last_check'] ?? 0))?></b></div><?php if($status==='isolated'): ?><div class="node-row"><span>离线时间</span><b><?=h(fmt_time($node['offline_since'] ?? 0))?></b></div><?php endif; ?></div><?php endforeach; ?></div></div></section>
<?php elseif($section==='usage'): ?>
<section class="section"><div class="section-head"><h2>流量统计</h2><span class="hint">统计更新：<?=h(fmt_time($usage['updated_at'] ?? 0))?>，<?=h(fmt_age($usage['updated_at'] ?? 0))?>；流量统计时间：<?=h($usagePeriodText)?></span></div><div class="summary"><div class="metric"><span>端口总流量</span><b><?=h(bytes_text($usage['port_total_bytes'] ?? 0))?></b></div><div class="metric good"><span>最常用端口</span><b><?=h(isset($topPortUsage['port']) ? ('端口 '.$topPortUsage['port']) : '—')?></b></div><div class="metric"><span>当前出口统计</span><b><?=h(bytes_text($activeOutboundUsageTotal ?? 0))?></b></div><div class="metric good"><span>当前标签</span><b><?=h($activeOutboundUsageTitle)?></b></div><div class="metric warn"><span>流量统计时间</span><b><?=h($usagePeriodText)?></b></div><div class="metric"><span>计数开始</span><b style="font-size:15px"><?=h($usageResetAt>0 ? fmt_time($usageResetAt) : '—')?></b></div></div><div class="card"><div class="section-head"><h3>各 IXR 端口流量统计</h3><span class="hint">按 10186、10187 等入口端口拆分，统计口径：<?=h($usagePeriodRange)?>。</span></div><?php if(empty($usage['available'])): ?><p class="hint">统计暂不可用：<?=h($usage['error'] ?? '等待采集')?></p><?php elseif(empty($usagePorts)): ?><p class="hint">还没有端口统计数据，等待下一次采集或产生新流量。</p><?php else: ?><div class="table-wrap"><table class="usage-table"><thead><tr><th>监听端口</th><th>使用占比</th><th>总量</th><th>上传</th><th>下载</th><th>规则数</th><th>默认出口</th></tr></thead><tbody><?php foreach($usagePorts as $port): ?><tr><td><b>端口 <?=h($port['port'] ?? '')?></b></td><td><div class="bar"><i style="width:<?=h(max(0,min(100,floatval($port['percent'] ?? 0))))?>%"></i></div><span class="hint"><?=h($port['percent'] ?? 0)?>%</span></td><td><?=h(bytes_text($port['total'] ?? 0))?></td><td><?=h(bytes_text($port['uplink'] ?? 0))?></td><td><?=h(bytes_text($port['downlink'] ?? 0))?></td><td><?=h($port['rules'] ?? 0)?> 条</td><td><?=h($port['default'] ?? 'auto-fast')?></td></tr><?php endforeach; ?></tbody></table></div><?php endif; ?></div><div class="card"><div class="section-head"><h3>各 IXR 出口流量统计</h3><span class="hint">可切换查看全部端口或单个监听端口；当前计数时间：<?=h($usagePeriodRange)?>。</span></div><div class="tabs"><a class="tab <?=$activeUsagePort===0?'active':''?>" href="<?=h(section_url('usage'))?>">全部端口</a><?php foreach($usagePortGroups as $group): $gp=intval($group['port'] ?? 0); ?><a class="tab <?=$activeUsagePort===$gp?'active':''?>" href="/admin.php?section=usage&usage_port=<?=h($gp)?>">端口 <?=h($gp)?></a><?php endforeach; ?></div><?php if(empty($usage['available'])): ?><p class="hint">统计暂不可用：<?=h($usage['error'] ?? '等待采集')?></p><?php elseif(empty($activeOutboundUsageNodes)): ?><p class="hint">当前标签暂无出口统计数据，等待下一次采集或产生新流量。</p><?php else: ?><div class="table-wrap"><table class="usage-table"><thead><tr><th>出口节点</th><th>使用占比</th><th>总量</th><th>上传</th><th>下载</th><th>本地端口</th></tr></thead><tbody><?php foreach($activeOutboundUsageNodes as $node): ?><tr><td><b><?=h($node['name'] ?? '')?></b></td><td><div class="bar"><i style="width:<?=h(max(0,min(100,floatval($node['percent'] ?? 0))))?>%"></i></div><span class="hint"><?=h($node['percent'] ?? 0)?>%</span></td><td><?=h(bytes_text($node['total'] ?? 0))?></td><td><?=h(bytes_text($node['uplink'] ?? 0))?></td><td><?=h(bytes_text($node['downlink'] ?? 0))?></td><td>127.0.0.1:<?=h($node['port'] ?? '')?></td></tr><?php endforeach; ?></tbody></table></div><?php endif; ?></div></section>
<?php elseif($section==='ports'): ?>
<section class="section"><div class="section-head"><h2>IXR 端口路由</h2></div><div class="tabs"><?php foreach($state['ports'] as $p): ?><a class="tab <?=intval($p['port'])===$activePort?'active':''?>" href="<?=h(section_url('ports',intval($p['port'])))?>">端口 <?=h($p['port'])?> <small><?=count($p['rules']??[])?> 条规则</small></a><?php endforeach; ?></div><?php if($activePortConfig): $p=$activePortConfig; $portKey=(string)$p['port']; $link=vmess_link($p,$export); ?><div class="split"><div><div class="card"><div class="section-head"><h3>IXR 端口 <?=h($p['port'])?> 的路由规则</h3><form method="post" action="<?=h(section_url('ports',$p['port']))?>" onsubmit="return confirm('确定删除端口 <?=h($p['port'])?>？')"><input type="hidden" name="section" value="ports"><input type="hidden" name="act" value="delete_port"><input type="hidden" name="port" value="<?=h($p['port'])?>"><button type="submit" class="btn red">删除端口</button></form></div><?php if(empty($p['rules'])): ?><p class="hint">当前端口没有强制规则，全部流量走 auto-fast 自动低延迟出口。</p><?php endif; ?><?php foreach(($p['rules']??[]) as $i=>$r): ?><div class="rule"><div class="rule-head"><strong><?=h($r['name'] ?? ('规则 '.($i+1)))?></strong><form method="post" action="<?=h(section_url('ports',$p['port']))?>" onsubmit="return confirm('确定删除这条规则？删除后会立即应用。')"><input type="hidden" name="section" value="ports"><input type="hidden" name="act" value="delete_rule"><input type="hidden" name="port" value="<?=h($p['port'])?>"><input type="hidden" name="rule_id" value="<?=h($r['id'] ?? '')?>"><input type="hidden" name="idx" value="<?=h($i)?>"><button type="submit" class="btn red">删除</button></form></div><form method="post" action="<?=h(section_url('ports',$p['port']))?>"><input type="hidden" name="section" value="ports"><input type="hidden" name="act" value="save_rule"><input type="hidden" name="port" value="<?=h($p['port'])?>"><input type="hidden" name="rule_id" value="<?=h($r['id'] ?? '')?>"><input type="hidden" name="idx" value="<?=h($i)?>"><div class="grid"><div><label>规则名称</label><input name="name" value="<?=h($r['name'] ?? '')?>"></div><div><label>出口</label><select name="outbound"><?php foreach($smartPools as $pool): ?><option value="<?=h($pool['name'])?>" <?=($r['outbound'] ?? '')===$pool['name']?'selected':''?>><?=h($pool['name'])?>（IXR 自动出口池）</option><?php endforeach; ?><?php foreach($outs as $o): ?><option value="<?=h($o['name'])?>" <?=($r['outbound'] ?? '')===$o['name']?'selected':''?>><?=h($o['name'])?></option><?php endforeach; ?><?php foreach($localIps as $ip): $val='localip:'.$ip; ?><option value="<?=h($val)?>" <?=($r['outbound'] ?? '')===$val?'selected':''?>><?=h(local_ip_label($ip))?></option><?php endforeach; ?></select></div></div><label>域名匹配</label><textarea name="domains" placeholder="每行一个，例如 domain:chatgpt.com 或 geosite:google"><?=h($r['domains'] ?? '')?></textarea><label>IP 匹配，可留空</label><textarea name="ips" placeholder="每行一个，例如 geoip:telegram 或 1.1.1.1/32"><?=h($r['ips'] ?? '')?></textarea><button type="submit" class="btn">保存规则</button></form></div><?php endforeach; ?></div><div class="card"><h3>新增规则</h3><form method="post" action="<?=h(section_url('ports',$p['port']))?>"><input type="hidden" name="section" value="ports"><input type="hidden" name="act" value="add_rule"><input type="hidden" name="port" value="<?=h($p['port'])?>"><div class="grid"><div><label>规则名称</label><input name="name" placeholder="例如 YouTube 走 US"></div><div><label>选择出口</label><select name="outbound"><?php foreach($smartPools as $pool): ?><option value="<?=h($pool['name'])?>"><?=h($pool['name'])?>（IXR 自动出口池）</option><?php endforeach; ?><?php foreach($outs as $o): ?><option value="<?=h($o['name'])?>"><?=h($o['name'])?></option><?php endforeach; ?><?php foreach($localIps as $ip): $val='localip:'.$ip; ?><option value="<?=h($val)?>"><?=h(local_ip_label($ip))?></option><?php endforeach; ?></select></div></div><label>域名匹配</label><textarea name="domains" placeholder="每行一个：domain:example.com / geosite:google"></textarea><label>IP 匹配，可留空</label><textarea name="ips" placeholder="每行一个：geoip:telegram / 8.8.8.8/32"></textarea><button type="submit" class="btn green">添加规则并应用</button></form></div></div><aside><div class="card"><h3>VMess 导入</h3><form method="post" action="<?=h(section_url('ports',$p['port']))?>"><input type="hidden" name="section" value="ports"><input type="hidden" name="act" value="save_export_port"><input type="hidden" name="port" value="<?=h($p['port'])?>"><label>导出别名</label><input name="alias" value="<?=h($export['aliases'][$portKey] ?? ('IXR-'.$portKey))?>"><button type="submit" class="btn ghost">保存别名</button></form><form method="post" action="<?=h(section_url('ports',$p['port']))?>"><input type="hidden" name="section" value="ports"><input type="hidden" name="act" value="save_export_global"><input type="hidden" name="port" value="<?=h($p['port'])?>"><label>默认连接地址</label><input name="default_address" value="<?=h($export['default_address'])?>" placeholder="例如你的前置转发域名或 IP"><button type="submit" class="btn ghost">保存连接地址</button></form><p class="hint">这里只影响网页生成的 VMess 导入链接，不影响 Xray 实际监听和路由。</p><label>Base64 VMess 链接</label><textarea class="vmess-box" id="vmess-<?=h($p['port'])?>" readonly><?=h($link)?></textarea><div class="copy-row"><button type="button" class="btn green" onclick="copyVmess('<?=h($p['port'])?>')">复制导入链接</button><span class="copy-ok" id="copy-ok-<?=h($p['port'])?>"></span></div><p class="hint">连接地址：<?=h($export['default_address'])?>；用户 ID：<?=h($p['uuid'])?></p></div><div class="card"><h3>端口设置</h3><form method="post" action="<?=h(section_url('ports',$p['port']))?>"><input type="hidden" name="section" value="ports"><input type="hidden" name="act" value="save_port"><input type="hidden" name="port" value="<?=h($p['port'])?>"><label>用户 ID / UUID</label><input name="uuid" value="<?=h($p['uuid'])?>"><label>用户邮箱标识</label><input name="email" value="<?=h($p['email'])?>"><button type="submit" class="btn">保存端口设置</button></form></div></aside></div><?php endif; ?></section>
<?php elseif($section==='pools'): ?>
<section class="section"><div class="section-head"><h2>IXR 自动出口池</h2></div><div class="grid"><?php foreach($smartPools as $pool): $members=$pool['members'] ?? []; $keyword=trim((string)($pool['keyword'] ?? '')); $candidateCount=0; foreach($outs as $o){ $n=(string)($o['name'] ?? ''); if(in_array($n,$members,true) || ($keyword!=='' && stripos($n,$keyword)!==false)) $candidateCount++; } ?><div class="card"><div class="section-head"><h3><?=h($pool['name'])?></h3><span class="hint"><?=h($candidateCount)?> 个候选出口</span></div><form method="post" action="<?=h(section_url('pools'))?>"><input type="hidden" name="section" value="pools"><input type="hidden" name="act" value="save_pool"><input type="hidden" name="pool_id" value="<?=h($pool['id'])?>"><label>自动包含关键词</label><input name="keyword" value="<?=h($keyword)?>" placeholder="例如 DN42；留空则只使用下面手动勾选的出口"><p class="hint">出口名称里包含这个关键词时会自动加入池；例如 DN42 会自动包含所有 DN42 节点。</p><label>手动加入出口</label><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:8px;margin:8px 0 14px"><?php foreach($outs as $o): $name=(string)($o['name'] ?? ''); $node=$healthNodes[$name] ?? []; $auto=($keyword!=='' && stripos($name,$keyword)!==false); $checked=in_array($name,$members,true); ?><label style="display:flex;gap:8px;align-items:flex-start;border:1px solid #e5eaf3;border-radius:12px;padding:9px;background:<?= $auto ? '#eff6ff' : '#fff' ?>"><input type="checkbox" name="members[]" value="<?=h($name)?>" <?=$checked?'checked':''?>><span><b><?=h($name)?></b><br><small class="hint"><?=h($auto?'关键词自动包含':'手动可选')?> · <?=h(status_label($node['status'] ?? 'unknown'))?> · <?=h(latency_text($node))?></small></span></label><?php endforeach; ?></div><button type="submit" class="btn">保存这个自动池</button></form><?php if(empty($pool['builtin'])): ?><form method="post" action="<?=h(section_url('pools'))?>" onsubmit="return confirm('确定删除自动池 <?=h($pool['name'])?>？')" style="margin-top:10px"><input type="hidden" name="section" value="pools"><input type="hidden" name="act" value="delete_pool"><input type="hidden" name="pool_id" value="<?=h($pool['id'])?>"><button type="submit" class="btn red">删除自动池</button></form><?php endif; ?></div><?php endforeach; ?></div><div class="card" style="margin-top:16px"><h3>新增 IXR 自动出口池</h3><form method="post" action="<?=h(section_url('pools'))?>" class="grid"><input type="hidden" name="section" value="pools"><input type="hidden" name="act" value="add_pool"><div><label>池名称</label><input name="name" placeholder="例如 AI智能自动、欧洲自动池"></div><div><label>自动包含关键词</label><input name="keyword" placeholder="可选，例如 EU、US、DN42"></div><div style="align-self:end"><button type="submit" class="btn green">添加自动池</button></div></form></div></section>
<?php elseif($section==='outbounds'): ?>
<section class="section">
  <div class="section-head">
    <h2>IXR 出口管理</h2>
  </div>
  <div class="summary">
    <div class="metric"><span>IXR 自管出口</span><b><?=h(count($customOuts))?></b></div>
    <div class="metric good"><span>参与调度</span><b><?=h($healthActive)?></b></div>
    <div class="metric bad"><span>已剔除</span><b><?=h($healthOffline)?></b></div>
    <div class="metric"><span>配置来源</span><b style="font-size:15px">IXR 独立</b></div>
  </div>
  <div class="split">
    <div class="card">
      <div class="section-head"><h3>导入 VMess 出口</h3><span class="hint">同名导入会更新现有出口。</span></div>
      <form method="post" action="<?=h(section_url('outbounds'))?>">
        <input type="hidden" name="section" value="outbounds"><input type="hidden" name="act" value="import_vmess">
        <div class="grid"><div><label>出口别名，可留空</label><input name="name" placeholder="留空使用 VMess 里的 ps 名称"></div><div><label>本地探测端口，可留空</label><input name="probe_port" placeholder="留空自动分配，例如 31220"></div></div>
        <label>VMess 链接</label><textarea name="vmess_link" placeholder="vmess://..." style="min-height:120px"></textarea>
        <button type="submit" class="btn green">导入并应用</button>
      </form>
    </div>
    <div class="card">
      <div class="section-head"><h3>手动新增出口</h3></div>
      <form method="post" action="<?=h(section_url('outbounds'))?>">
        <input type="hidden" name="section" value="outbounds"><input type="hidden" name="act" value="save_custom_outbound"><input type="hidden" name="custom_outbound_name" value="">
        <div class="grid">
          <div><label>出口名称</label><input name="name" placeholder="例如 Example-US"></div>
          <div><label>本地探测端口</label><input name="probe_port" placeholder="留空自动分配"></div>
          <div><label>服务器地址</label><input name="address" placeholder="域名或 IP"></div>
          <div><label>远端端口</label><input name="remote_port" placeholder="例如 15637"></div>
          <div><label>用户 ID / UUID</label><input name="id" placeholder="VMess UUID"></div>
          <div><label>AlterID</label><input name="aid" value="0"></div>
          <div><label>加密 security</label><input name="security" value="auto"></div>
          <div><label>传输 network</label><input name="network" value="tcp"></div>
          <div><label>伪装 type</label><input name="header_type" value="none"></div>
          <div><label>TLS</label><input name="tls" placeholder="留空 / tls"></div>
        </div>
        <button type="submit" class="btn green">新增并应用</button>
      </form>
    </div>
  </div>
  <?php
    $activeOutboundName=trim((string)($_GET['edit_outbound'] ?? ''));
    $activeCustomOutbound=null;
    foreach($customOuts as $candidate){ if($activeOutboundName!=='' && (string)($candidate['name'] ?? '')===$activeOutboundName){ $activeCustomOutbound=$candidate; break; } }
  ?>
  <div class="section-head" style="margin-top:16px"><h3>当前 IXR 出口</h3></div>
  <?php if(empty($customOuts)): ?>
    <div class="card"><p class="hint">还没有 IXR 自管出口。可以从上方导入 VMess 或手动新增。</p></div>
  <?php else: ?>
    <div class="card">
      <div class="section-head"><h3>出口列表</h3><span class="hint">共 <?=h(count($customOuts))?> 个；点名称或按钮进入编辑。</span></div>
      <div class="table-wrap">
        <table class="usage-table">
          <thead><tr><th>出口名称</th><th>本地探测端</th><th>服务器地址</th><th>远端端口</th><th>TCP连接延迟</th><th>实测访问延迟</th><th>操作</th></tr></thead>
          <tbody>
          <?php foreach($customOuts as $co): $node=$healthNodes[$co['name']] ?? []; $probe=intval($co['probe_port'] ?? $co['port'] ?? 0); $isSelected=((string)($co['name'] ?? '')===$activeOutboundName); $editUrl=section_url('outbounds',0,['edit_outbound'=>$co['name'] ?? '']); ?>
            <tr style="<?=$isSelected?'background:#eff6ff':''?>">
              <td><b><a href="<?=h($editUrl)?>" style="color:#1d4ed8;text-decoration:none"><?=h($co['name'] ?? '')?></a></b></td>
              <td>127.0.0.1:<?=h($probe)?></td>
              <td><?=h($co['address'] ?? '')?></td>
              <td><?=h($co['remote_port'] ?? '')?></td>
              <td><b><?=h(tcp_latency_text($node))?></b></td>
              <td><b><?=h(latency_text($node))?></b></td>
              <td><a class="btn edit" href="<?=h($editUrl)?>">编辑</a></td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
    <?php if($activeOutboundName!=='' && !$activeCustomOutbound): ?>
      <div class="card"><p class="hint">没有找到这个出口，可能已经被删除。请从上面的列表重新选择。</p></div>
    <?php elseif($activeCustomOutbound): $co=$activeCustomOutbound; $node=$healthNodes[$co['name']] ?? []; $probe=intval($co['probe_port'] ?? $co['port'] ?? 0); ?>
      <div class="card">
        <div class="section-head"><h3>编辑：<?=h($co['name'])?></h3><span class="status-badge <?=h(status_class($node['status'] ?? 'unknown'))?>"><?=h(status_label($node['status'] ?? 'unknown'))?></span></div>
        <form method="post" action="<?=h(section_url('outbounds'))?>">
          <input type="hidden" name="section" value="outbounds"><input type="hidden" name="act" value="save_custom_outbound"><input type="hidden" name="custom_outbound_name" value="<?=h($co['name'])?>">
          <div class="grid">
            <div><label>出口名称</label><input name="name" value="<?=h($co['name'])?>"></div>
            <div><label>本地探测端口</label><input name="probe_port" value="<?=h($probe)?>"></div>
            <div><label>服务器地址</label><input name="address" value="<?=h($co['address'] ?? '')?>"></div>
            <div><label>远端端口</label><input name="remote_port" value="<?=h($co['remote_port'] ?? '')?>"></div>
            <div><label>用户 ID / UUID</label><input name="id" value="<?=h($co['id'] ?? '')?>"></div>
            <div><label>AlterID</label><input name="aid" value="<?=h($co['aid'] ?? 0)?>"></div>
            <div><label>加密 security</label><input name="security" value="<?=h($co['security'] ?? 'auto')?>"></div>
            <div><label>传输 network</label><input name="network" value="<?=h($co['network'] ?? 'tcp')?>"></div>
            <div><label>伪装 type</label><input name="header_type" value="<?=h($co['header_type'] ?? 'none')?>"></div>
            <div><label>TLS</label><input name="tls" value="<?=h($co['tls'] ?? '')?>" placeholder="留空 / tls"></div>
            <div><label>Host</label><input name="host" value="<?=h($co['host'] ?? '')?>"></div>
            <div><label>Path</label><input name="path" value="<?=h($co['path'] ?? '')?>"></div>
            <div><label>SNI</label><input name="sni" value="<?=h($co['sni'] ?? '')?>"></div>
            <div><label>ALPN</label><input name="alpn" value="<?=h($co['alpn'] ?? '')?>"></div>
            <div><label>Fingerprint</label><input name="fp" value="<?=h($co['fp'] ?? '')?>"></div>
            <div><label>允许不安全</label><input name="insecure" value="<?=h($co['insecure'] ?? '0')?>" placeholder="0 或 1"></div>
          </div>
          <p class="hint">TCP连接延迟：<?=h(tcp_latency_text($node))?>；实测访问延迟：<?=h(latency_text($node))?>；远端：<?=h($co['address'] ?? '')?>:<?=h($co['remote_port'] ?? '')?>；探测：127.0.0.1:<?=h($probe)?></p>
          <button type="submit" class="btn">保存并应用</button>
        </form>
        <form method="post" action="<?=h(section_url('outbounds'))?>" onsubmit="return confirm('确定删除 IXR 出口 <?=h($co['name'])?>？相关 IX 线路、用户授权、自动池和端口规则引用会一起移除。')" style="margin-top:10px">
          <input type="hidden" name="section" value="outbounds"><input type="hidden" name="act" value="delete_custom_outbound"><input type="hidden" name="custom_outbound_name" value="<?=h($co['name'])?>">
          <button type="submit" class="btn red">删除 IXR 出口</button>
        </form>
      </div>
    <?php else: ?>
      <div class="card"><p class="hint">请选择一个出口进行编辑。</p></div>
    <?php endif; ?>
  <?php endif; ?>
</section>
<?php elseif($section==='account'): ?>
<section class="section"><div class="card"><h2>修改密码</h2><form method="post" action="<?=h(section_url('account'))?>" class="grid"><input type="hidden" name="section" value="account"><input type="hidden" name="act" value="change_admin_password"><input type="hidden" name="csrf" value="<?=h($adminCsrf)?>"><div><label>当前密码</label><input name="current_password" type="password" required autocomplete="current-password"></div><div><label>新密码</label><input name="new_password" type="password" required minlength="8" maxlength="200" autocomplete="new-password"></div><div><label>确认新密码</label><input name="confirm_password" type="password" required minlength="8" maxlength="200" autocomplete="new-password"></div><div style="align-self:end"><button type="submit" class="btn">修改密码</button></div></form></div></section>
<?php elseif($section==='ix-admin'): ?>
<section class="section"><iframe id="ixAdminFrame" class="embed-frame" src="/ix-admin.php?embedded=1" title="统一出口管理"></iframe></section>
<?php elseif($section==='add-port'): ?>
<section class="section"><div class="card"><h2>新增 IXR 端口</h2><form method="post" action="<?=h(section_url('add-port'))?>" class="grid"><input type="hidden" name="section" value="ports"><input type="hidden" name="act" value="add_port"><div><label>端口</label><input name="port" placeholder="例如 10188"></div><div style="align-self:end"><button type="submit" class="btn green">添加端口并应用</button></div></form></div></section>
<?php endif; ?>
</main></div><script>
document.querySelectorAll('.tab').forEach(function(link){
  link.addEventListener('click',function(event){
    var href=link.getAttribute('href');
    if(!href || href==='#') return;
    event.preventDefault();
    window.location.assign(href);
  });
});
function copyVmess(port){var box=document.getElementById('vmess-'+port);var ok=document.getElementById('copy-ok-'+port);function done(){if(ok){ok.textContent='已复制';setTimeout(function(){ok.textContent='';},1600);}}if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(box.value).then(done).catch(function(){box.select();document.execCommand('copy');done();});}else{box.select();document.execCommand('copy');done();}}
</script></body></html>
