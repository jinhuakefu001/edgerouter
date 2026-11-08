<?php
/**
 * Smoke tests — `php tests/smoke.php`
 *
 * 不依赖 PHPUnit，直接跑，退出码非 0 表示有失败。
 */

declare(strict_types=1);

require_once __DIR__ . '/../lib/detect.php';

$pass = 0;
$fail = 0;

function check(string $label, $actual, $expected): void
{
    global $pass, $fail;
    if ($actual === $expected) {
        $pass++;
        return;
    }
    $fail++;
    fwrite(STDERR, sprintf("FAIL  %-42s got %s, want %s\n",
        $label,
        var_export($actual, true),
        var_export($expected, true)));
}

// ------------------------------------------------------------------
// UA 指纹
// ------------------------------------------------------------------
$cases = [
    'wechat-iphone' => [
        'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 MicroMessenger/8.0.30',
        ['client' => 'wechat', 'device' => 'mobile', 'os' => 'ios', 'is_bot' => false],
    ],
    'android-chrome' => [
        'Mozilla/5.0 (Linux; Android 13; M2012K11AC) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36',
        ['client' => 'browser', 'device' => 'mobile', 'os' => 'android', 'is_bot' => false],
    ],
    'ipad-safari' => [
        'Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1',
        ['client' => 'browser', 'device' => 'tablet', 'os' => 'ios', 'is_bot' => false],
    ],
    'desktop-windows' => [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
        ['client' => 'browser', 'device' => 'desktop', 'os' => 'windows', 'is_bot' => false],
    ],
    'qq-inapp' => [
        'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 MQQBrowser/12.0 Mobile Safari/537.36',
        ['client' => 'qq', 'device' => 'mobile', 'os' => 'android', 'is_bot' => false],
    ],
    'alipay-inapp' => [
        'Mozilla/5.0 (Linux; Android 11) AppleWebKit/537.36 AlipayClient/10.3 Mobile Safari/537.36',
        ['client' => 'alipay', 'device' => 'mobile', 'os' => 'android', 'is_bot' => false],
    ],
    'sqlmap' => [
        'sqlmap/1.7.2#stable (https://sqlmap.org)',
        ['is_bot' => true],
    ],
    'curl' => [
        'curl/8.4.0',
        ['is_bot' => true],
    ],
    'python-requests' => [
        'python-requests/2.31.0',
        ['is_bot' => true],
    ],
    'googlebot' => [
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        ['is_bot' => true],
    ],
    'empty-ua' => [
        '',
        ['client' => 'none', 'device' => 'unknown', 'is_bot' => true],
    ],
];

foreach ($cases as $label => [$ua, $expect]) {
    $got = Detect::fingerprint($ua);
    foreach ($expect as $k => $v) {
        check("$label.$k", $got[$k], $v);
    }
}

// ------------------------------------------------------------------
// CIDR
// ------------------------------------------------------------------
check('cidr /16 in',    Detect::inCidr('192.168.1.5', '192.168.0.0/16'), true);
check('cidr /16 out',   Detect::inCidr('192.169.1.5', '192.168.0.0/16'), false);
check('cidr /8 in',     Detect::inCidr('10.1.2.3', '10.0.0.0/8'), true);
check('cidr /8 out',    Detect::inCidr('8.8.8.8', '10.0.0.0/8'), false);
check('cidr exact',     Detect::inCidr('1.2.3.4', '1.2.3.4'), true);
check('cidr /32 in',    Detect::inCidr('1.2.3.4', '1.2.3.4/32'), true);
check('cidr /32 out',   Detect::inCidr('1.2.3.5', '1.2.3.4/32'), false);
check('cidr /0',        Detect::inCidr('9.9.9.9', '0.0.0.0/0'), true);
check('cidr invalid',   Detect::inCidr('not-an-ip', '10.0.0.0/8'), false);

// ------------------------------------------------------------------
// 汇总
// ------------------------------------------------------------------
echo "\n{$pass} passed, {$fail} failed\n";
exit($fail > 0 ? 1 : 0);
