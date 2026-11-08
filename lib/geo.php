<?php
/**
 * GeoIP lookup against an ip2region xdb file.
 *
 * xdb 是纯二进制、mmap 友好的格式：256 字节头 + 256×256 的向量索引 + 段数据。
 * 这里只把 512 KB 向量索引读进内存，段数据按需 fseek，所以单次查询约 1-2 次磁盘读。
 *
 * 数据来源：https://github.com/lionsoul2014/ip2region  (Apache-2.0)
 */

declare(strict_types=1);

final class GeoIp
{
    private $fh = null;
    private string $vIndex = '';
    private int $startPtr = 0;
    private bool $tried = false;

    public function __construct(private string $xdbPath)
    {
    }

    /**
     * @return array{country:string,province:string,city:string,isp:string,cc:string,raw:string}
     */
    public function lookup(string $ip): array
    {
        $empty = ['country' => '', 'province' => '', 'city' => '', 'isp' => '', 'cc' => '', 'raw' => ''];

        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $empty;
        }
        $this->open();
        if ($this->fh === null) {
            return $empty;
        }

        $ipInt = ip2long($ip);
        if ($ipInt === false) {
            return $empty;
        }
        if ($ipInt < 0) {
            $ipInt += 4294967296;
        }

        $i0 = ($ipInt >> 24) & 0xFF;
        $i1 = ($ipInt >> 16) & 0xFF;
        $idx = $i0 * 256 * 8 + $i1 * 8;

        $sPtr = (int)unpack('V', substr($this->vIndex, $idx, 4))[1];
        $ePtr = (int)unpack('V', substr($this->vIndex, $idx + 4, 4))[1];
        if ($sPtr <= 0 || $ePtr <= 0 || $ePtr < $sPtr) {
            return $empty;
        }

        $segCount = intdiv($ePtr - $sPtr, 14);
        if ($segCount <= 0) {
            return $empty;
        }

        $lo = 0;
        $hi = $segCount - 1;
        while ($lo <= $hi) {
            $mid = ($lo + $hi) >> 1;
            if (fseek($this->fh, $sPtr + $mid * 14) !== 0) {
                break;
            }
            $seg = fread($this->fh, 14);
            if ($seg === false || strlen($seg) !== 14) {
                break;
            }
            $u = unpack('Vsip/Veip/vlen/Vptr', $seg);

            if ($ipInt < $u['sip']) {
                $hi = $mid - 1;
            } elseif ($ipInt > $u['eip']) {
                $lo = $mid + 1;
            } else {
                $len = (int)$u['len'];
                $ptr = (int)$u['ptr'];
                if ($len <= 0 || $len > 512) {
                    return $empty;
                }
                if (fseek($this->fh, $ptr) !== 0) {
                    return $empty;
                }
                $raw = fread($this->fh, $len);
                if ($raw === false) {
                    return $empty;
                }
                return self::parse((string)$raw);
            }
        }
        return $empty;
    }

    /**
     * xdb v4 记录：`国家|省|市|ISP|国家代码`
     * 旧 v2 记录：`国家|区域|省|市|ISP`
     */
    private static function parse(string $raw): array
    {
        $p = explode('|', $raw);
        $clean = static function (int $i) use ($p): string {
            $v = isset($p[$i]) ? trim((string)$p[$i]) : '';
            return ($v === '0' || $v === '') ? '' : $v;
        };

        $isV4 = isset($p[4]) && preg_match('/^[A-Z]{2}$/', (string)$p[4]);
        if ($isV4) {
            return [
                'country'  => $clean(0),
                'province' => $clean(1),
                'city'     => $clean(2),
                'isp'      => $clean(3),
                'cc'       => (string)$p[4],
                'raw'      => $raw,
            ];
        }
        return [
            'country'  => $clean(0),
            'province' => $clean(2),
            'city'     => $clean(3),
            'isp'      => $clean(4),
            'cc'       => '',
            'raw'      => $raw,
        ];
    }

    private function open(): void
    {
        if ($this->tried) {
            return;
        }
        $this->tried = true;

        if (!is_file($this->xdbPath)) {
            return;
        }
        $h = @fopen($this->xdbPath, 'rb');
        if (!$h) {
            return;
        }
        $hdr = fread($h, 256);
        if ($hdr === false || strlen($hdr) !== 256) {
            fclose($h);
            return;
        }
        $this->startPtr = (int)unpack('V', substr($hdr, 8, 4))[1];
        if ($this->startPtr < 256) {
            fclose($h);
            return;
        }
        $vIndex = fread($h, 256 * 256 * 8);
        if ($vIndex === false || strlen($vIndex) !== 256 * 256 * 8) {
            fclose($h);
            return;
        }
        $this->vIndex = $vIndex;
        $this->fh = $h;
    }

    public function __destruct()
    {
        if (is_resource($this->fh)) {
            fclose($this->fh);
        }
    }
}
