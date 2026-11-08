<?php
/**
 * Request fingerprinting: client type, device class, bot detection.
 * Pure regex, no IO, no dependencies.
 */

declare(strict_types=1);

final class Detect
{
    /** 明确是自动化程序的 UA 特征 */
    private const BOT = [
        'bot', 'crawler', 'spider', 'scrapy', 'curl', 'wget', 'httpie',
        'python-requests', 'python-urllib', 'go-http-client', 'java/', 'okhttp',
        'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'nuclei', 'nikto',
        'headlesschrome', 'phantomjs', 'selenium', 'puppeteer', 'playwright',
        'facebookexternalhit', 'whatsapp', 'telegrambot', 'slackbot',
        'monitor', 'uptime', 'pingdom', 'statuscake', 'site24x7',
    ];

    /** 内嵌浏览器 / App 客户端 */
    private const CLIENT = [
        'wechat'    => ['micromessenger'],
        'qq'        => ['qq/', 'mqqbrowser', 'qzone'],
        'alipay'    => ['alipayclient'],
        'weibo'     => ['weibo'],
        'douyin'    => ['aweme', 'bytedance'],
        'dingtalk'  => ['dingtalk'],
        'feishu'    => ['lark', 'feishu'],
        'instagram' => ['instagram'],
        'fbapp'     => ['fbav', 'fban'],
        'line'      => [' line/'],
    ];

    private const MOBILE = [
        'iphone', 'ipod', 'android', 'mobile', 'windows phone',
        'blackberry', 'opera mini', 'iemobile',
    ];

    private const TABLET = ['ipad', 'tablet', 'kindle', 'silk', 'playbook'];

    /**
     * @return array{ua:string,client:string,device:string,os:string,is_bot:bool}
     */
    public static function fingerprint(?string $ua = null): array
    {
        $ua    = $ua ?? ($_SERVER['HTTP_USER_AGENT'] ?? '');
        $lower = strtolower($ua);

        if (trim($ua) === '') {
            return ['ua' => '', 'client' => 'none', 'device' => 'unknown', 'os' => '', 'is_bot' => true];
        }

        $isBot = false;
        foreach (self::BOT as $needle) {
            if (strpos($lower, $needle) !== false) {
                $isBot = true;
                break;
            }
        }

        $client = 'browser';
        foreach (self::CLIENT as $name => $needles) {
            foreach ($needles as $needle) {
                if (strpos($lower, $needle) !== false) {
                    $client = $name;
                    break 2;
                }
            }
        }

        $device = 'desktop';
        foreach (self::TABLET as $needle) {
            if (strpos($lower, $needle) !== false) {
                $device = 'tablet';
                break;
            }
        }
        if ($device === 'desktop') {
            foreach (self::MOBILE as $needle) {
                if (strpos($lower, $needle) !== false) {
                    $device = 'mobile';
                    break;
                }
            }
        }

        $os = 'other';
        foreach ([
            'ios'      => ['iphone', 'ipad', 'ipod'],
            'android'  => ['android'],
            'harmony'  => ['harmonyos', 'openharmony'],
            'windows'  => ['windows nt'],
            'macos'    => ['macintosh', 'mac os x'],
            'linux'    => ['linux'],
        ] as $name => $needles) {
            foreach ($needles as $needle) {
                if (strpos($lower, $needle) !== false) {
                    $os = $name;
                    break 2;
                }
            }
        }

        return ['ua' => $ua, 'client' => $client, 'device' => $device, 'os' => $os, 'is_bot' => $isBot];
    }

    /** 取真实客户端 IP，按可信代理链从右往左剥 */
    public static function clientIp(int $trustedHops = 0): string
    {
        $remote = (string)($_SERVER['REMOTE_ADDR'] ?? '');

        $candidates = [];
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $candidates[] = (string)$_SERVER['HTTP_CF_CONNECTING_IP'];
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            foreach (explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR']) as $part) {
                $candidates[] = trim($part);
            }
        }
        if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            $candidates[] = (string)$_SERVER['HTTP_X_REAL_IP'];
        }
        $candidates[] = $remote;

        $candidates = array_values(array_filter($candidates, static function ($ip) {
            return filter_var($ip, FILTER_VALIDATE_IP) !== false;
        }));
        if (!$candidates) {
            return $remote;
        }
        if ($trustedHops <= 0) {
            return $candidates[0];
        }
        // 从右往左数，跳过 trustedHops 个代理
        $idx = max(0, count($candidates) - 1 - $trustedHops);
        return $candidates[$idx];
    }

    /** CIDR 匹配（IPv4） */
    public static function inCidr(string $ip, string $cidr): bool
    {
        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }
        [$subnet, $bits] = explode('/', $cidr, 2);
        $bits = (int)$bits;
        if ($bits < 0 || $bits > 32) {
            return false;
        }
        $ipLong     = ip2long($ip);
        $subnetLong = ip2long($subnet);
        if ($ipLong === false || $subnetLong === false) {
            return false;
        }
        if ($bits === 0) {
            return true;
        }
        $mask = -1 << (32 - $bits);
        return ($ipLong & $mask) === ($subnetLong & $mask);
    }
}
