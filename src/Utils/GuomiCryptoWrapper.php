<?php

declare(strict_types=1);

namespace Allesx\CgbPayment\Utils;

use Rtgm\sm\RtSm2;
use Rtgm\sm\RtSm3;
use Rtgm\sm\RtSm4;
use Exception;

class GuomiCryptoWrapper
{
    private RtSm2 $sm2;
    private RtSm3 $sm3;

    public function __construct()
    {
        $this->sm2 = new RtSm2('hex', true);
        $this->sm3 = new RtSm3();
    }

    public static function isSupported(): bool
    {
        return class_exists(RtSm2::class) &&
            class_exists(RtSm3::class) &&
            class_exists(RtSm4::class) &&
            extension_loaded('gmp');
    }

    private function isValidHexKey(string $key): bool
    {
        if (empty($key)) {
            return false;
        }
        $len = strlen($key);
        if ($len !== 64 && $len !== 128 && $len !== 130) {
            return false;
        }
        if (!ctype_xdigit($key)) {
            return false;
        }
        return true;
    }

    private function safeSm2Call(callable $callback, ...$args)
    {
        try {
            return $callback(...$args);
        } catch (\Error $e) {
            throw new Exception('SM2操作失败: ' . $e->getMessage());
        } catch (Exception $e) {
            throw new Exception('SM2操作失败: ' . $e->getMessage());
        }
    }

    public function sm2Encrypt(string $data, string $publicKeyHex): string
    {
        try {
            if (!$this->isValidHexKey($publicKeyHex)) {
                throw new Exception('公钥格式无效，必须是128位或130位十六进制字符串');
            }
            if (strlen($publicKeyHex) === 130 && substr($publicKeyHex, 0, 2) === '04') {
                $publicKeyHex = substr($publicKeyHex, 2);
            }
            $encrypted = $this->safeSm2Call([$this->sm2, 'doEncrypt'], $data, $publicKeyHex);
            return $encrypted;
        } catch (Exception $e) {
            throw new Exception('SM2加密失败: ' . $e->getMessage());
        }
    }

    public function sm4Decrypt(string $encryptedData, string $key, string $mode = 'cbc', ?string $iv = null): string
    {
        try {
            $binaryKey = hex2bin($key);
            if ($binaryKey === false) {
                throw new Exception('密钥不是有效的十六进制字符串');
            }
            if ($iv === null) {
                $iv = substr(md5($key), 0, 32);
            } else {
                if (strlen($iv) === 16 && !ctype_xdigit($iv)) {
                    $iv = bin2hex($iv);
                } elseif (strlen($iv) !== 32 || !ctype_xdigit($iv)) {
                    $ivBin = @hex2bin($iv);
                    if ($ivBin !== false && strlen($ivBin) === 16) {
                        $iv = bin2hex($ivBin);
                    } else {
                        throw new Exception('IV格式无效，必须是32个HEX字符或16字节二进制');
                    }
                }
            }
            $sm4 = new RtSm4($binaryKey);
            $sm4Mode = $mode === 'cbc' ? 'sm4-cbc' : 'sm4-' . $mode;
            $decrypted = $sm4->decrypt($encryptedData, $sm4Mode, $iv, 'hex');
            return $decrypted;
        } catch (Exception $e) {
            throw new Exception('SM4解密失败: ' . $e->getMessage());
        }
    }
}


