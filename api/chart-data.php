<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/helpers.php';

security_headers();
$user = Auth::requireConsole();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

// 1. Hourly buckets for last 24h: success vs failed
$timeline = DB::query(
    "SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:00') AS bucket,
            SUM(event_type = 'login_success') AS s,
            SUM(event_type = 'login_failed')  AS f
     FROM auth_logs
     WHERE created_at >= NOW() - INTERVAL 24 HOUR
     GROUP BY bucket
     ORDER BY bucket ASC"
);
// Fill missing hours with zeroes
$labels = []; $succ = []; $fail = [];
$now = time();
for ($i = 23; $i >= 0; $i--) {
    $stamp = date('Y-m-d H:00', $now - $i * 3600);
    $labels[] = date('H:00', $now - $i * 3600);
    $found = null;
    foreach ($timeline as $row) {
        if ($row['bucket'] === $stamp) { $found = $row; break; }
    }
    $succ[] = $found ? (int) $found['s'] : 0;
    $fail[] = $found ? (int) $found['f'] : 0;
}

// 2. Event type counts (last 24h)
$events = DB::query(
    "SELECT event_type, COUNT(*) c FROM auth_logs
     WHERE created_at >= NOW() - INTERVAL 24 HOUR
     GROUP BY event_type ORDER BY c DESC"
);

// 3. Top 10 source IPs (last 24h)
$ips = DB::query(
    "SELECT ip_address, COUNT(*) c FROM auth_logs
     WHERE created_at >= NOW() - INTERVAL 24 HOUR
     GROUP BY ip_address ORDER BY c DESC LIMIT 10"
);

// 4. Threat flag distribution
$threats = DB::query(
    "SELECT threat_flag, COUNT(*) c FROM auth_logs
     WHERE created_at >= NOW() - INTERVAL 7 DAY AND threat_flag <> 'none'
     GROUP BY threat_flag ORDER BY c DESC"
);

echo json_encode([
    'timeline' => [
        'labels'   => $labels,
        'success'  => $succ,
        'failed'   => $fail,
    ],
    'events'  => array_map(fn($r) => ['label' => $r['event_type'], 'value' => (int) $r['c']], $events),
    'ips'     => array_map(fn($r) => ['label' => $r['ip_address'], 'value' => (int) $r['c']], $ips),
    'threats' => array_map(fn($r) => ['label' => $r['threat_flag'], 'value' => (int) $r['c']], $threats),
    'ts' => date('c'),
]);
