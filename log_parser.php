<?php
$log_file = '/www/sec_firewall/security_log.txt';
$reasons = [];
$ips = [];

if (file_exists($log_file)) {
    $lines = file($log_file);
    foreach ($lines as $line) {
        // Extract reason
        if (preg_match('/Reason:\s(.*?)\s-\sIP:/', $line, $matches)) {
            $reason = $matches[1];
            $reasons[$reason] = ($reasons[$reason] ?? 0) + 1;
        }
        // Extract IP
        if (preg_match('/IP:\s([\d\.]+)/', $line, $ip_match)) {
            $ip = $ip_match[1];
            $ips[$ip] = ($ips[$ip] ?? 0) + 1;
        }
    }
    arsort($reasons);
    arsort($ips);
    $top_ips = array_slice($ips, 0, 30, true);
} else {
    die("Log file not found.");
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Blocked reasons report - Security Log</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        canvas {
            width: 100% !important;
            height: auto !important;
            max-width: 100%;
            margin: auto;
            display: block;
        }
    </style>
</head>
<body>

<h2>Blocked reasons report - Security Log</h2>

<table>
    <tr>
        <th>Most Common Reason</th>
        <th>Count</th>
    </tr>
    <?php foreach ($reasons as $reason => $count): ?>
    <tr>
        <td><?= htmlspecialchars($reason) ?></td>
        <td><?= $count ?></td>
    </tr>
    <?php endforeach; ?>
</table>

<h3>Most Common Reason - Visual Chart</h3>
<canvas id="reasonChart"></canvas>

<h2>Top 30 IP's mostly blocked</h2>
<table>
    <tr>
        <th>IP</th>
        <th>Count</th>
    </tr>
    <?php foreach ($top_ips as $ip => $count): ?>
    <tr>
        <td><?= htmlspecialchars($ip) ?></td>
        <td><?= $count ?></td>
    </tr>
    <?php endforeach; ?>
</table>

<h3>Most Blocked IP's - Visual Chart</h3>
<canvas id="ipChart"></canvas>

<script>
    // Chart for Reasons
    const ctx1 = document.getElementById('reasonChart').getContext('2d');
    const reasonChart = new Chart(ctx1, {
        type: 'bar',
        data: {
            labels: <?= json_encode(array_keys($reasons)) ?>,
            datasets: [{
                label: 'Count',
                data: <?= json_encode(array_values($reasons)) ?>,
                backgroundColor: 'rgba(255, 99, 132, 0.5)'
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: { ticks: { autoSkip: false, maxRotation: 60, minRotation: 45 } }
            }
        }
    });

    // Chart for IPs
    const ctx2 = document.getElementById('ipChart').getContext('2d');
    const ipChart = new Chart(ctx2, {
        type: 'bar',
        data: {
            labels: <?= json_encode(array_keys($top_ips)) ?>,
            datasets: [{
                label: 'Count',
                data: <?= json_encode(array_values($top_ips)) ?>,
                backgroundColor: 'rgba(54, 162, 235, 0.5)'
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    ticks: {
                        autoSkip: false,
                        maxRotation: 60,
                        minRotation: 45
                    }
                }
            }
        }
    });
</script>

</body>
</html>
