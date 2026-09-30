<?php
declare(strict_types=1);

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

$query = (string)($_SERVER['QUERY_STRING'] ?? '');
header('Location: /' . ($query !== '' ? '?' . $query : ''), true, 302);
exit;
