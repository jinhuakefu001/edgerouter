# edgerouter

**按 IP、设备、客户端、路径把请求分发出去 —— 规则写在 JSON 里，不改代码。**

单文件入口 + 两个小类，零依赖，任何 PHP 7.4+ 环境都能跑。

```php
// 一条规则就是一次决策
{ "name": "mobile-to-m-site",
  "when": { "device": ["mobile", "tablet"] },
  "action": "redirect",
  "targets": { "url": "https://m.example.com{path}" } }
```

---

## 为什么不用 nginx 的 if / map

nginx 能做简单分流，但一旦规则变复杂就变成灾难：

- 判断「是否微信内置浏览器」要写一段 UA 正则，改一次要 reload
- 要按 IP 归属地分流，得额外装 GeoIP 模块 + 定期更数据
- 想灰度 10% 流量，`split_clients` 只能按固定 hash，无法和其他条件组合
- 规则一多，`map` 嵌套到看不清谁先谁后

`edgerouter` 把这些收进一个有序规则表：**从上往下，命中第一条就执行**。改规则是改 JSON，热生效，不用 reload 任何服务。

它也**不负责内容** —— 只做「这个请求该去哪」的决策，然后 302 或直接拒绝。所以能放在任何 Web 服务器前面，也可以作为 PHP-FPM 里的 `auto_prepend_file`。

---

## 快速开始

```bash
git clone <this-repo> edgerouter && cd edgerouter
cp rules.example.json rules.json          # 改成你自己的规则
mkdir -p data

# 下载 IP 库（可选，不用归属地规则就不需要）
wget -O data/ip2region_v4.xdp \
  https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region_v4.xdb
mv data/ip2region_v4.xdp data/ip2region_v4.xdb

php -S 127.0.0.1:8080 router.php          # 本地试
```

nginx 接入：

```nginx
location / {
    try_files $uri $uri/ @router;
}
location @router {
    fastcgi_pass unix:/run/php-fpm/www.sock;
    fastcgi_param SCRIPT_FILENAME /var/www/edgerouter/router.php;
    include fastcgi_params;
}
```

---

## 规则结构

```json
{
  "default": { "redirect": "https://example.com/" },
  "rules": [
    { "name": "...", "when": { ... }, "action": "...", "targets": { ... } }
  ]
}
```

`rules` 是**有序数组**，从上往下匹配，**命中第一条就停**。所以把最具体的规则放前面。

`default` 是所有规则都不命中时的兜底。

### `when` 条件

| 条件 | 值 | 说明 |
|---|---|---|
| `is_bot` | `true` / `false` | UA 是否像自动化程序（爬虫库、扫描器、无头浏览器） |
| `ua_missing` | `true` | UA 为空（很多扫描器不发 UA） |
| `device` | `mobile` `tablet` `desktop` | 设备类型 |
| `client` | `wechat` `qq` `alipay` `weibo` `douyin` `dingtalk` `feishu` `line` `browser` | 内嵌浏览器 |
| `os` | `ios` `android` `harmony` `windows` `macos` `linux` | 系统 |
| `ua_contains` | 字符串数组 | UA 子串匹配（自定义特征） |
| `country` | 字符串数组 | 国家名，如 `中国` / `United States` |
| `cc` | 字符串数组 | 两位国家代码，如 `CN` `US` |
| `province` / `city` / `isp` | 字符串数组 | 省市 / 运营商 |
| `cidr` | CIDR 数组 | 如 `10.0.0.0/8` |
| `path_prefix` | 字符串数组 | 路径前缀 |
| `path_regex` | 正则 | 复杂路径匹配 |
| `method` | 数组 | `GET` `POST` … |
| `header` | 对象 | `{"accept-language": "zh"}`，子串匹配 |
| `hour_range` | `[9, 18]` | 服务器时区的小时范围 |
| `weekday` | `[1..7]` 数组 | 1=周一 |

**多个条件之间是 AND**，同一个条件的多个值是 OR。

```json
"when": { "device": ["mobile"], "cc": ["CN"] }
```
= 移动端 **且** 国家是中国。

### `action`

| 动作 | 参数 | 行为 |
|---|---|---|
| `redirect` | `targets`、`status` | 302 跳转（可设 301/307） |
| `block` | `status`、`message` | 返回错误页 |
| `render` | `file` | 输出指定的本地 HTML |
| `pass` | — | 不处理，交给 Web 服务器 |

### `targets` 与灰度

单目标：

```json
"targets": { "url": "https://m.example.com{path}" }
```

多目标按权重随机（灰度发布）：

```json
"targets": [
  { "url": "https://v2.example.com{path}", "weight": 10 },
  { "url": "https://example.com{path}",   "weight": 90 }
]
```

**注意**：权重是每次请求独立随机，不保证同一用户固定走同一个版本。需要粘性灰度的话，用 `header` 条件配合你自己的 cookie/分流键。

### 变量占位符

目标 URL 里可以用：

| 占位符 | 值 |
|---|---|
| `{country}` `{cc}` `{province}` `{city}` `{isp}` | GeoIP 结果（已 URL 编码） |
| `{device}` `{client}` `{os}` | 设备指纹 |
| `{path}` | 请求路径 |

### 限流

```json
{
  "name": "api-rate-limit",
  "when": { "path_prefix": ["/api/"] },
  "limit": { "count": 120, "window": 60 },
  "action": "pass"
}
```

固定窗口计数，按 `规则名 + IP` 分桶，文件锁保证并发安全。超限返回 429。

写盘失败时**放行** —— 限流组件自己挂掉不应该拖垮整站。

---

## 常见场景

### 拦截扫描器

```json
{ "name": "block-automation",
  "when": { "is_bot": true },
  "action": "block", "status": 403 }
```

内置特征覆盖 sqlmap / nikto / nmap / masscan / zgrab / nuclei / 无头浏览器 / 各类 HTTP 库。

### 移动端分流

```json
{ "name": "mobile",
  "when": { "device": ["mobile", "tablet"] },
  "action": "redirect",
  "targets": { "url": "https://m.example.com{path}" } }
```

### 海外导向国际站

```json
{ "name": "intl",
  "when": { "cc": ["US", "GB", "DE", "JP"] },
  "action": "redirect",
  "targets": { "url": "https://intl.example.com/" } }
```

### App 内浏览器引导用户跳出

很多 App 的内置浏览器限制下载、限制跳转。识别出来后渲染一个「请用系统浏览器打开」的页面：

```json
{ "name": "in-app-browser",
  "when": { "client": ["wechat", "qq", "weibo"], "path_prefix": ["/download"] },
  "action": "render",
  "file": "pages/open-in-browser.html" }
```

---

## 性能

| 操作 | 耗时 |
|---|---|
| 规则匹配（10 条） | < 0.1 ms |
| UA 指纹 | < 0.05 ms（纯正则） |
| GeoIP 查询 | ~0.3 ms（只读 512 KB 向量索引，段数据 fseek） |
| 限流（文件锁） | ~0.2 ms |

GeoIP 是**惰性加载**：规则里没用到 `country`/`province`/`cc` 就不打开 xdb 文件。

---

## 注意事项

- **`TRUSTED_PROXY_HOPS` 必须配对**。如果你在前面挂了 Cloudflare + nginx 两层代理却设成 0，取到的「客户端 IP」其实是代理 IP，按 IP 做的所有判断都不准。反过来设得太大，攻击者伪造的 `X-Forwarded-For` 会被当真。
- **`path_regex` 会跑用户输入**。别写有灾难性回溯的正则（`(a+)+$` 这类），否则一个请求能烧掉 CPU。
- **规则顺序即优先级**。把 `block-automation` 放在最前面，否则扫描器可能先命中后面的跳转规则。
- **`pass` 动作本身不输出内容**，只是 `http_response_code(404)` 退出，把请求交回服务器。如果你用 `php -S` 直接跑 `router.php`，`pass` 的表现是 404。
- 日志写到 `data/access.log`（JSON Lines），**自己做过期清理**，否则一天几十万行会撑爆磁盘。

---

## 目录

```
edgerouter/
├── router.php            # 入口：上下文 → 规则匹配 → 动作
├── lib/
│   ├── geo.php           # GeoIp 类，ip2region xdb 查询
│   └── detect.php        # Detect 类，UA 指纹 / 客户端 IP / CIDR
├── rules.example.json    # 示例规则
├── pages/                # render 动作用的页面
└── data/                 # ip2region xdb、限流状态、访问日志（不入库）
```

---

## License

MIT
