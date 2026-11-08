<?php
/**
 * edgerouter — rule-based request router for edge deployments.
 *
 * 一个入口，按「IP 归属地 / 设备类型 / 客户端 / UA / 路径 / 请求头」把请求
 * 分派到不同目标，或直接拒绝。规则写在 rules.json，改规则不用改代码。
 *
 * 典型用途：
 *   - 移动端和桌面端走不同站点
 *   - 海外流量导到国际站，国内导向国内站
 *   - 灰度发布：按权重把 10% 流量切到新版本
 *   - 拦截扫描器与自动化程序
 *   - 按地域做合规分流
 */

declare(strict_types=1);

require_once __DIR__ . '/lib/geo.php';
require_once __DIR__ . '/lib/detect.php';

// ============================================================
// 配置
// ============================================================
const CONFIG_FILE   = __DIR__ . '/rules.json';
const XDB_FILE      = __DIR__ . '/data/ip2region_v4.xdb';
const RATE_DIR      = __DIR__ . '/data/rate';
const LOG_FILE      = __DIR__ . '/data/access.log';

// 信任几层反向代理（Cloudflare/nginx 等）。0 = 直接取 X-Forwarded-For 第一段
const TRUSTED_PROXY_HOPS = 0;

// ============================================================
// 上下文
// ============================================================
final class Context
{
    public string $ip;
    public array  $geo;
    public array  $fp;
    public string $path;
    public string $method;
    public array  $headers;
    public int    $now;

    public function __construct()
    {
        $this->ip      = Detect::clientIp(TRUSTED_PROXY_HOPS);
        $this->fp      = Detect::fingerprint();
        $this->path    = (string)(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/');
        $this->method  = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $this->now     = time();
        $this->headers = self::collectHeaders();
        $this->geo     = ['country' => '', 'province' => '', 'city' => '', 'isp' => '', 'cc' => '', 'raw' => ''];
    }

    /** 惰性查 GeoIP：规则里没用到归属地就不读文件 */
    public function geo(): array
    {
        static $geo = null;
        if ($geo === null) {
            $geo = (new GeoIp(XDB_FILE))->lookup($this->ip);
        }
        return $geo;
    }

    private static function collectHeaders(): array
    {
        $out = [];
        foreach ($_SERVER as $k => $v) {
            if (strpos($k, 'HTTP_') === 0) {
                $out[strtolower(str_replace('_', '-', substr($k, 5)))] = (string)$v;
            }
        }
        return $out;
    }
}

// ============================================================
// 规则匹配
// ============================================================
final class Rules
{
    /**
     * when 里所有条件都必须满足（AND）。数组型条件内部是 OR。
     */
    public static function matches(array $when, Context $ctx): bool
    {
        foreach ($when as $key => $expect) {
            switch ($key) {
                case 'is_bot':
                    if ($ctx->fp['is_bot'] !== (bool)$expect) {
                        return false;
                    }
                    break;

                case 'device':
                    if (!in_array($ctx->fp['device'], (array)$expect, true)) {
                        return false;
                    }
                    break;

                case 'client':
                    if (!in_array($ctx->fp['client'], (array)$expect, true)) {
                        return false;
                    }
                    break;

                case 'os':
                    if (!in_array($ctx->fp['os'], (array)$expect, true)) {
                        return false;
                    }
                    break;

                case 'ua_contains':
                    $ua = strtolower($ctx->fp['ua']);
                    $hit = false;
                    foreach ((array)$expect as $needle) {
                        if (strpos($ua, strtolower((string)$needle)) !== false) {
                            $hit = true;
                            break;
                        }
                    }
                    if (!$hit) {
                        return false;
                    }
                    break;

                case 'ua_missing':
                    if ($expect && $ctx->fp['ua'] !== '') {
                        return false;
                    }
                    break;

                case 'country':
                    $g = $ctx->geo();
                    if (!in_array($g['country'], (array)$expect, true)) {
                        return false;
                    }
                    break;

                case 'cc':
                    $g = $ctx->geo();
                    if (!in_array($g['cc'], (array)$expect, true)) {
                        return false;
                    }
                    break;

                case 'province':
                    $g = $ctx->geo();
                    if (!in_array($g['province'], (array)$expect, true)) {
                        return false;
                    }
                    break;

                case 'city':
                    $g = $ctx->geo();
                    if (!in_array($g['city'], (array)$expect, true)) {
                        return false;
                    }
                    break;

                case 'isp':
                    $g = $ctx->geo();
                    if (!in_array($g['isp'], (array)$expect, true)) {
                        return false;
                    }
                    break;

                case 'cidr':
                    $ok = false;
                    foreach ((array)$expect as $block) {
                        if (Detect::inCidr($ctx->ip, (string)$block)) {
                            $ok = true;
                            break;
                        }
                    }
                    if (!$ok) {
                        return false;
                    }
                    break;

                case 'path_prefix':
                    $ok = false;
                    foreach ((array)$expect as $prefix) {
                        if (strpos($ctx->path, (string)$prefix) === 0) {
                            $ok = true;
                            break;
                        }
                    }
                    if (!$ok) {
                        return false;
                    }
                    break;

                case 'path_regex':
                    if (!preg_match((string)$expect, $ctx->path)) {
                        return false;
                    }
                    break;

                case 'method':
                    if (!in_array($ctx->method, array_map('strtoupper', (array)$expect), true)) {
                        return false;
                    }
                    break;

                case 'header':
                    // {"header": {"accept-language": "zh-CN"}}  子串匹配
                    foreach ((array)$expect as $name => $needle) {
                        $name = strtolower((string)$name);
                        if (!isset($ctx->headers[$name])) {
                            return false;
                        }
                        if ($needle !== '' && stripos($ctx->headers[$name], (string)$needle) === false) {
                            return false;
                        }
                    }
                    break;

                case 'hour_range':
                    // [9, 18] 表示 9:00–18:59（服务器本地时区）
                    $h = (int)date('G', $ctx->now);
                    [$from, $to] = (array)$expect + [0, 0];
                    if ($h < $from || $h > $to) {
                        return false;
                    }
                    break;

                case 'weekday':
                    $w = (int)date('N', $ctx->now);   // 1=Mon … 7=Sun
                    if (!in_array($w, (array)$expect, true)) {
                        return false;
                    }
                    break;

                default:
                    // 未知条件一律不匹配，避免写错规则导致全量放行
                    return false;
            }
        }
        return true;
    }

    /** 从多个目标里按权重挑一个 */
    public static function pickTarget(array $targets): string
    {
        if (isset($targets['url'])) {
            return (string)$targets['url'];
        }
        $total = 0;
        foreach ($targets as $t) {
            $total += max(0, (int)($t['weight'] ?? 1));
        }
        if ($total <= 0) {
            return '';
        }
        $roll = random_int(1, $total);
        foreach ($targets as $t) {
            $roll -= max(0, (int)($t['weight'] ?? 1));
            if ($roll <= 0) {
                return (string)($t['url'] ?? '');
            }
        }
        return (string)($targets[0]['url'] ?? '');
    }

    /** 把 {country} 这类占位符换成实际值 */
    public static function expand(string $tpl, Context $ctx): string
    {
        if (strpos($tpl, '{') === false) {
            return $tpl;
        }
        $geo = $ctx->geo();
        $vars = [
            '{country}'  => rawurlencode($geo['country']),
            '{cc}'       => rawurlencode($geo['cc']),
            '{province}' => rawurlencode($geo['province']),
            '{city}'     => rawurlencode($geo['city']),
            '{isp}'      => rawurlencode($geo['isp']),
            '{device}'   => $ctx->fp['device'],
            '{client}'   => $ctx->fp['client'],
            '{os}'       => $ctx->fp['os'],
            '{path}'     => $ctx->path,
        ];
        return strtr($tpl, $vars);
    }
}

// ============================================================
// 限流（固定窗口，文件锁）
// ============================================================
final class Limiter
{
    public static function allow(string $key, int $limit, int $windowSec): bool
    {
        if ($limit <= 0) {
            return true;
        }
        if (!is_dir(RATE_DIR)) {
            @mkdir(RATE_DIR, 0755, true);
        }
        $file = RATE_DIR . '/' . md5($key) . '.json';
        $fp = @fopen($file, 'c+');
        if (!$fp) {
            return true;   // 无法写盘时放行，避免限流变成单点故障
        }
        $ok = true;
        if (flock($fp, LOCK_EX)) {
            $size = filesize($file);
            $data = $size > 0 ? json_decode((string)fread($fp, $size), true) : null;
            $now  = time();

            if (!is_array($data) || ($now - (int)($data['start'] ?? 0)) >= $windowSec) {
                $data = ['start' => $now, 'count' => 0];
            }
            $data['count'] = (int)($data['count'] ?? 0) + 1;
            $ok = $data['count'] <= $limit;

            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode($data));
            fflush($fp);
            flock($fp, LOCK_UN);
        }
        fclose($fp);
        return $ok;
    }
}

// ============================================================
// 响应
// ============================================================
final class Respond
{
    public static function block(int $status, string $message = 'Forbidden'): void
    {
        http_response_code($status);
        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><meta charset="utf-8"><title>', $status, '</title>',
             '<div style="font:16px/1.6 system-ui;max-width:32em;margin:15vh auto;text-align:center">',
             '<h1 style="font-size:3em;margin:0;color:#999">', $status, '</h1>',
             '<p>', htmlspecialchars($message, ENT_QUOTES), '</p></div>';
        exit;
    }

    public static function redirect(string $url, int $status = 302): void
    {
        if (!preg_match('#^https?://#i', $url)) {
            self::block(500, 'Invalid redirect target');
        }
        header('Location: ' . $url, true, $status);
        header('Cache-Control: no-store, no-cache, must-revalidate');
        exit;
    }

    public static function render(string $file): void
    {
        if (!is_file($file)) {
            self::block(404, 'Not found');
        }
        header('Content-Type: text/html; charset=utf-8');
        readfile($file);
        exit;
    }
}

function write_log(Context $ctx, string $rule, string $action, string $target): void
{
    if (!is_dir(dirname(LOG_FILE))) {
        @mkdir(dirname(LOG_FILE), 0755, true);
    }
    $geo = $ctx->geo();
    $line = json_encode([
        'ts'     => gmdate('c', $ctx->now),
        'ip'     => $ctx->ip,
        'rule'   => $rule,
        'action' => $action,
        'target' => $target,
        'path'   => $ctx->path,
        'device' => $ctx->fp['device'],
        'client' => $ctx->fp['client'],
        'bot'    => $ctx->fp['is_bot'],
        'geo'    => $geo['country'] . '/' . $geo['province'] . '/' . $geo['city'],
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    @file_put_contents(LOG_FILE, $line . "\n", FILE_APPEND | LOCK_EX);
}

// ============================================================
// 主流程
// ============================================================
$ctx = new Context();

if (!is_file(CONFIG_FILE)) {
    Respond::block(500, 'rules.json not found');
}
$cfg = json_decode((string)file_get_contents(CONFIG_FILE), true);
if (!is_array($cfg)) {
    Respond::block(500, 'rules.json is not valid JSON');
}

$hitRule = null;
foreach (($cfg['rules'] ?? []) as $rule) {
    if (!is_array($rule)) {
        continue;
    }
    if (isset($rule['enabled']) && !$rule['enabled']) {
        continue;
    }
    if (!Rules::matches((array)($rule['when'] ?? []), $ctx)) {
        continue;
    }
    $hitRule = $rule;
    break;
}

if ($hitRule === null) {
    $fallback = $cfg['default'] ?? null;
    if (!$fallback) {
        Respond::block(404, 'No matching rule');
    }
    if (isset($fallback['redirect'])) {
        Respond::redirect((string)$fallback['redirect']);
    }
    Respond::render((string)($fallback['render'] ?? ''));
}

$name   = (string)($hitRule['name'] ?? 'unnamed');
$action = strtolower((string)($hitRule['action'] ?? 'pass'));

// 限流优先于动作
if (isset($hitRule['limit'])) {
    $l = (array)$hitRule['limit'];
    $allowed = Limiter::allow(
        $name . ':' . $ctx->ip,
        (int)($l['count'] ?? 60),
        (int)($l['window'] ?? 60)
    );
    if (!$allowed) {
        write_log($ctx, $name, 'ratelimit', '');
        Respond::block(429, 'Too many requests');
    }
}

switch ($action) {
    case 'block':
        write_log($ctx, $name, 'block', '');
        Respond::block((int)($hitRule['status'] ?? 403), (string)($hitRule['message'] ?? 'Forbidden'));
        break;

    case 'redirect':
        $url = Rules::expand(Rules::pickTarget((array)($hitRule['targets'] ?? [])), $ctx);
        write_log($ctx, $name, 'redirect', $url);
        Respond::redirect($url, (int)($hitRule['status'] ?? 302));
        break;

    case 'render':
        write_log($ctx, $name, 'render', (string)($hitRule['file'] ?? ''));
        Respond::render(__DIR__ . '/' . ltrim((string)($hitRule['file'] ?? ''), '/'));
        break;

    case 'pass':
    default:
        write_log($ctx, $name, 'pass', '');
        // 交回 Web 服务器处理静态文件
        http_response_code(404);
        exit;
}
