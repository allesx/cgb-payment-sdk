<?php

declare(strict_types=1);

namespace Allesx\CgbPayment\Client;

use Allesx\CgbPayment\Exception\PayException;
use Allesx\CgbPayment\Utils\GuomiCryptoWrapper;
use Allesx\CgbPayment\Utils\SystemUtils;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use Psr\Log\LoggerInterface;
use Exception;
use GuzzleHttp\Client as GuzzleClient;

class CgbClient
{
    private array $config;
    private ?LoggerInterface $logger;

    public function __construct(array $config, ?LoggerInterface $logger = null)
    {
        $this->config = $config;
        $this->logger = $logger;
        $this->validateConfig();
    }
    
    public function validateConfig(): void
    {
        $required = [
            'app_id', 'ent_cst_no', 'ent_user_id', 'ent_password',
            'gateway_url', 'private_key', 'private_key_pass', 'public_key',
        ];
        foreach ($required as $field) {
            if (empty($this->config[$field])) {
                throw new PayException("缺少配置参数: {$field}");
            }
        }
        if (empty($this->config['version'])) {
            $this->config['version'] = '2.0.0';
        }
        if (empty($this->config['sign_algo'])) {
            $this->config['sign_algo'] = 'SHA1';
        }
    }

    public function request(string $tradeCode, array $body): array
    {
        return $this->sendCompleteRequest($body, $tradeCode);
    }

    public function sendCompleteRequest(array $requestBody, string $tradeCode): array
    {
        try {
            $now = new \DateTimeImmutable('now');
            $passwordPlain = $this->config['ent_password'];
            $passwordEnvelope = $this->generatePasswordEnvelopeIfPossible($passwordPlain);
            $seqNo = $now->format('Y-m-d\TH:i:s.') . str_pad($now->format('v'), 3, '0', STR_PAD_LEFT);

            $reqArr = [
                'Header' => [
                    'appId' => $this->config['app_id'],
                    'entCstNo' => $this->config['ent_cst_no'],
                    'entUserId' => $this->config['ent_user_id'],
                    'macAddr' => SystemUtils::getMacAddress($this->config['mac_address'] ?? ''),
                    'password' => $passwordEnvelope,
                    'resdFlag' => "Y",
                    'seqNo' => $seqNo,
                    'tradeCode' => $tradeCode,
                    'tranDate' => $now->format('Ymd'),
                    'tranTime' => $now->format('His'),
                ],
                'Body' => $requestBody,
            ];
            $reqString = json_encode($reqArr, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            $this->debug('CGB:STEP1:reqString', ['reqString' => $reqString]);

            $signature = $this->generateSignature($reqString);
            $this->debug('CGB:STEP2:signature', ['signature' => $signature, 'algo' => strtoupper($this->config['sign_algo'] ?? 'SHA1')]);

            $secretKey = $this->generateSecretKey();
            $this->debug('CGB:STEP3:sm4Key', ['secretKey_hex' => bin2hex($secretKey)]);

            $encryptedBody = $this->encryptContentWithSecretKey($reqString, $secretKey);
            $this->debug('CGB:STEP4:encryptedBody', ['encryptedBody' => $encryptedBody]);

            $encryptedKey = $this->encryptSecretKey($secretKey);
            $this->debug('CGB:STEP5:encryptKey', ['encryptedKey' => $encryptedKey]);

            $headers = [
                'appId: ' . $this->config['app_id'],
                'encryptKey: ' . $encryptedKey,
                'signature: ' . $signature,
                'Content-Type: text/plain; charset=UTF-8',
            ];

            $url = rtrim($this->config['gateway_url'], '/') . '/' . $tradeCode . '/' . ($this->config['version'] ?? '2.0.0');
            $this->debug('CGB:STEP6:request', ['url' => $url, 'headers' => $headers, 'body' => $encryptedBody]);

            $res = $this->sendRequest($url, $headers, $encryptedBody);
            $respHeaders = $res['headers'] ?? [];
            $respEncryptKey = $respHeaders['encryptKey'] ?? ($respHeaders['EncryptKey'] ?? '');
            $respSignature = $respHeaders['signature'] ?? ($respHeaders['Signature'] ?? '');
            $respBodyRaw = $res['body'] ?? '';
            $this->debug('CGB:STEP7:responseRaw', ['headers' => $respHeaders, 'body' => $respBodyRaw]);

            $decrypt = $this->processResponseDecryption($respEncryptKey, $respSignature, $respBodyRaw);

            return [
                'status' => $res['status'] ?? 'failed',
                'headers' => $respHeaders,
                'raw' => $respBodyRaw,
                'decrypted' => $decrypt['decrypted'],
                'parsed' => $decrypt['parsed'],
                'decrypt_error' => $decrypt['decryptError'],
            ];
        } catch (Exception $e) {
            throw new PayException('CGB请求失败:' . $e->getMessage());
        }
    }

    private function processResponseDecryption(string $respEncryptKey, string $respSignature, string $respBodyRaw): array
    {
        $decrypted = '';
        $parsed = null;
        $decryptError = null;

        try {
            $respKeyBytes = $this->decryptSecretKey($respEncryptKey);
            $decrypted = $this->decryptContentSmart($respBodyRaw, $respKeyBytes);
            if (empty($decrypted)) {
                $decryptError = '解密后的内容为空';
            } else {
                if (!empty($respSignature) && !$this->verifySignature($decrypted, $respSignature)) {
                    $decryptError = '响应验签失败';
                }
                $try = json_decode($decrypted, true);
                if (json_last_error() === JSON_ERROR_NONE) {
                    $parsed = $try;
                } else {
                    $decryptError = 'JSON解析失败: ' . json_last_error_msg();
                }
            }
        } catch (Exception $e) {
            $decryptError = $e->getMessage();
        }

        return [
            'decrypted' => $decrypted,
            'parsed' => $parsed,
            'decryptError' => $decryptError,
        ];
    }

    private function sendRequest(string $url, array $headers, string $body): array
    {
        $headerAssoc = [];
        foreach ($headers as $h) {
            if (strpos($h, ':') !== false) {
                [$k, $v] = explode(':', $h, 2);
                $headerAssoc[trim($k)] = trim($v);
            }
        }

        $client = $this->config['http_client'] ?? null;
        if (!$client instanceof GuzzleClient) {
            $client = new GuzzleClient([
                'timeout' => (float)($this->config['timeout'] ?? 30),
                'http_errors' => false,
                'version' => 1.1,
            ]);
        }

        $response = $client->post($url, [
            'headers' => $headerAssoc,
            'body' => $body,
        ]);

        $statusCode = $response->getStatusCode();
        $respHeaders = [];
        foreach ($response->getHeaders() as $name => $values) {
            $respHeaders[$name] = implode(', ', $values);
        }
        $bodyStr = (string)$response->getBody();

        if ($statusCode !== 200) {
            throw new PayException('HTTP请求失败，状态码: ' . $statusCode);
        }

        return [
            'status' => 'success',
            'body' => $bodyStr,
            'headers' => $respHeaders,
            'http_code' => $statusCode,
        ];
    }

    public function generateSignature(string $content): string
    {
        try {
            $privateKey = $this->loadPrivateKey();
            $algo = strtoupper($this->config['sign_algo'] ?? 'SHA1');
            $algoConst = $algo === 'SHA1' ? OPENSSL_ALGO_SHA1 : OPENSSL_ALGO_SHA256;
            $signature = '';
            $binaryHash = hash($algo, $content, true);
            $prepared = strtolower(bin2hex($binaryHash));
            if (!openssl_sign($prepared, $signature, $privateKey, $algoConst)) {
                $errors = [];
                while (($err = openssl_error_string()) !== false) {
                    $errors[] = $err;
                }
                $errorMsg = !empty($errors) ? implode('; ', $errors) : '未知错误';
                throw new PayException('RSA签名失败: ' . $errorMsg);
            }
            return base64_encode($signature);
        } catch (Exception $e) {
            throw new PayException('生成签名失败:' . $e->getMessage());
        }
    }

    public function verifySignature(string $content, string $signatureB64): bool
    {
        try {
            $publicKey = $this->loadBankPublicKey();
            $signature = base64_decode($signatureB64, true);
            if ($signature === false) {
                return false;
            }
            $algo = strtoupper($this->config['sign_algo'] ?? 'SHA1');
            $algoConst = $algo === 'SHA1' ? OPENSSL_ALGO_SHA1 : OPENSSL_ALGO_SHA256;
            $binaryHash = hash($algo, $content, true);
            $prepared = strtolower(bin2hex($binaryHash));
            $result = openssl_verify($prepared, $signature, $publicKey, $algoConst);
            if ($result === 1) {
                return true;
            }
            if ($algo !== 'SHA1') {
                $fallbackBinaryHash = hash('SHA1', $content, true);
                $fallbackPrepared = strtolower(bin2hex($fallbackBinaryHash));
                $fallbackResult = openssl_verify($fallbackPrepared, $signature, $publicKey, OPENSSL_ALGO_SHA1);
                if ($fallbackResult === 1) {
                    return true;
                }
            }
            return false;
        } catch (Exception $e) {
            throw new PayException('验证签名失败:' . $e->getMessage());
        }
    }

    public function generateSecretKey(): string
    {
        try {
            return random_bytes(16);
        } catch (Exception $e) {
            throw new PayException('生成密钥失败:' . $e->getMessage());
        }
    }

    public function encryptSecretKey(string $secretKey): string
    {
        try {
            $publicKey = $this->loadBankPublicKey();
            $encrypted = '';
            if (!openssl_public_encrypt($secretKey, $encrypted, $publicKey, OPENSSL_PKCS1_PADDING)) {
                $errors = [];
                while (($err = openssl_error_string()) !== false) {
                    $errors[] = $err;
                }
                throw new PayException('银行公钥加密失败: ' . implode('; ', $errors));
            }
            return base64_encode($encrypted);
        } catch (Exception $e) {
            throw new PayException('加密密钥失败:' . $e->getMessage());
        }
    }

    public function decryptSecretKey(string $encryptKeyB64): string
    {
        $encrypted = base64_decode($encryptKeyB64, true);
        if ($encrypted === false) {
            throw new PayException('encryptKey Base64 解码失败');
        }
        try {
            $privateKey = $this->loadPrivateKey();
        } catch (Exception $e) {
            throw new PayException('加载私钥失败: ' . $e->getMessage());
        }
        $out = '';
        if (!openssl_private_decrypt($encrypted, $out, $privateKey, OPENSSL_PKCS1_PADDING)) {
            $errors = [];
            while (($err = openssl_error_string()) !== false) {
                $errors[] = $err;
            }
            $errorMsg = !empty($errors) ? implode('; ', $errors) : '未知错误';
            throw new PayException('私钥解密对称密钥失败: ' . $errorMsg);
        }
        if (strlen($out) !== 16) {
            throw new PayException("解密后的密钥长度不正确，期望16字节，实际" . strlen($out) . "字节");
        }
        return $out;
    }

    public function encryptContentWithSecretKey(string $content, string $secretKey): string
    {
        if (strlen($secretKey) !== 16) {
            throw new Exception('SM4 key must be 16 bytes');
        }
        $blockSize = 16;
        $pad = $blockSize - (strlen($content) % $blockSize);
        $content .= str_repeat(chr($pad), $pad);
        $ciphertext = openssl_encrypt($content, 'SM4-ECB', $secretKey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
        if ($ciphertext === false) {
            throw new Exception('SM4 ECB 加密失败');
        }
        return strtoupper(bin2hex($ciphertext));
    }

    public function decryptContentSmart(string $encryptedContent, string $secretKey): string
    {
        $data = null;
        $dataLength = strlen($encryptedContent);
        if ($encryptedContent !== '' && ctype_xdigit($encryptedContent) && ($dataLength % 2 === 0)) {
            $data = @hex2bin($encryptedContent);
            if ($data === false) {
                $data = base64_decode($encryptedContent, true);
            }
        } else {
            $data = base64_decode($encryptedContent, true);
            if ($data === false && $encryptedContent !== '') {
                $cleaned = preg_replace('/[^0-9a-fA-F]/', '', $encryptedContent);
                if (strlen($cleaned) % 2 === 0 && strlen($cleaned) > 0) {
                    $data = @hex2bin($cleaned);
                }
            }
        }
        if ($data === false || empty($data)) {
            return '';
        }
        $plainEcb = @openssl_decrypt($data, 'sm4-ecb', $secretKey, OPENSSL_RAW_DATA);
        if ($plainEcb !== false && !empty($plainEcb)) {
            return $this->cleanupPlaintext($plainEcb);
        }
        if (strlen($data) >= 16) {
            $iv = substr($data, -16);
            $cipher = substr($data, 0, -16);
            $plainCbc = @openssl_decrypt($cipher, 'sm4-cbc', $secretKey, OPENSSL_RAW_DATA, $iv);
            if ($plainCbc !== false && !empty($plainCbc)) {
                return $this->cleanupPlaintext($plainCbc);
            }
        }
        return '';
    }

    private function loadBankPublicKey()
    {
        $publicKey = $this->config['public_key'] ?? '';
        if (empty($publicKey)) {
            throw new PayException('银行公钥配置为空');
        }
        if (is_string($publicKey) && is_file($publicKey)) {
            $keyContent = @file_get_contents($publicKey);
            if ($keyContent === false) {
                throw new PayException("无法读取银行公钥文件: {$publicKey}");
            }
            $ext = strtolower(pathinfo($publicKey, PATHINFO_EXTENSION));
            if ($ext === 'cer' || !str_starts_with(trim($keyContent), '-----BEGIN')) {
                $pemContent = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($keyContent), 64, "\n") . "-----END CERTIFICATE-----\n";
                $cert = @openssl_x509_read($pemContent);
                if ($cert !== false) {
                    $pubKey = openssl_pkey_get_public($cert);
                    if ($pubKey !== false) {
                        return $pubKey;
                    }
                }
            } else {
                $cert = @openssl_x509_read($keyContent);
                if ($cert !== false) {
                    $pubKey = openssl_pkey_get_public($cert);
                    if ($pubKey !== false) {
                        return $pubKey;
                    }
                }
            }
            $res = @openssl_pkey_get_public($keyContent);
            if ($res !== false) {
                return $res;
            }
        } else {
            $res = @openssl_pkey_get_public($publicKey);
            if ($res !== false) {
                return $res;
            }
        }
        $errors = [];
        while (($err = openssl_error_string()) !== false) {
            $errors[] = $err;
        }
        $errorMsg = !empty($errors) ? implode('; ', $errors) : '未知错误';
        throw new PayException("无法加载银行公钥: {$errorMsg} ({$publicKey})");
    }

    private function loadPrivateKey()
    {
        $privateKey = $this->config['private_key'] ?? '';
        $privateKeyPass = $this->config['private_key_pass'] ?? '';
        if (empty($privateKey)) {
            throw new PayException('private_key 配置为空');
        }
        if (is_string($privateKey) && is_file($privateKey)) {
            $pkcs12 = @file_get_contents($privateKey);
            if ($pkcs12 === false) {
                throw new PayException("无法读取私钥文件: {$privateKey}");
            }
            $certs = [];
            if (@openssl_pkcs12_read($pkcs12, $certs, $privateKeyPass)) {
                if (!empty($certs['pkey'])) {
                    $res = @openssl_pkey_get_private($certs['pkey']);
                    if ($res !== false) {
                        return $res;
                    }
                }
                throw new PayException('PFX 文件中未找到私钥或密码错误');
            }
        } else {
            $res = @openssl_pkey_get_private($privateKey, $privateKeyPass);
            if ($res !== false) {
                return $res;
            }
        }
        $errors = [];
        while (($err = openssl_error_string()) !== false) {
            $errors[] = $err;
        }
        $errorMsg = !empty($errors) ? implode('; ', $errors) : '未知错误';
        throw new PayException("无法加载私钥: {$errorMsg} ({$privateKey})");
    }

    private function cleanupPlaintext(string $str): string
    {
        $str = preg_replace('/^\xEF\xBB\xBF/', '', $str);
        $str = preg_replace('/[\x00-\x1F\x7F]/u', '', $str);
        return trim((string)$str);
    }

    private function generatePasswordEnvelopeIfPossible(string $plainPassword): string
    {
        try {
            $pubHex = $this->config['bank_psw_enc_pub'] ?? getenv('CGB_PSW_ENC_PUB') ?: '';
            if (empty($pubHex)) {
                return $plainPassword;
            }
            return $this->sm2EncryptOperatorPwd($pubHex, $plainPassword);
        } catch (\Throwable $e) {
            return $plainPassword;
        }
    }

    private function sm2EncryptOperatorPwd(string $pubHex, string $operatorPwd): string
    {
        $len = strlen($operatorPwd);
        if ($len < 10) {
            $operatorPwd = '0' . $len . $operatorPwd;
        } elseif ($len >= 100) {
            return "888";
        } else {
            $operatorPwd = (string)$len . $operatorPwd;
        }
        $pubKeyBytes = hex2bin($pubHex);
        if ($pubKeyBytes === false) {
            throw new Exception('公钥 HEX 字符串解码失败');
        }
        $pwdBytes = $operatorPwd;
        $cipherHex = null;
        if (class_exists(GuomiCryptoWrapper::class) && GuomiCryptoWrapper::isSupported()) {
            try {
                $crypto = new GuomiCryptoWrapper();
                $cipherHex = $crypto->sm2Encrypt($pwdBytes, $pubHex);
                if (!empty($cipherHex)) {
                    if (!ctype_xdigit($cipherHex)) {
                        $cipherHex = bin2hex(base64_decode($cipherHex, true) ?: $cipherHex);
                    }
                    if (!str_starts_with(strtoupper($cipherHex), '30')) {
                        $cipherHex = $this->encodeSM2CipherToDER($cipherHex);
                    }
                }
            } catch (Exception $e) {
                // fallback below
            }
        }
        if (empty($cipherHex)) {
            throw new Exception('SM2 加密失败：无可用加密库');
        }
        return '====================' . strtoupper($cipherHex);
    }

    private function encodeSM2CipherToDER(string $c1c3c2Hex): string
    {
        $curveLength = 32;
        if (str_starts_with(strtolower($c1c3c2Hex), '04')) {
            $c1c3c2Hex = substr($c1c3c2Hex, 2);
        }
        $c1xHex = substr($c1c3c2Hex, 0, $curveLength * 2);
        $c1yHex = substr($c1c3c2Hex, $curveLength * 2, $curveLength * 2);
        $c3Hex = substr($c1c3c2Hex, $curveLength * 4, 32 * 2);
        $c2Hex = substr($c1c3c2Hex, $curveLength * 4 + 32 * 2);
        $c1xInt = new Integer($this->hexToDecimal($c1xHex));
        $c1yInt = new Integer($this->hexToDecimal($c1yHex));
        $c3Octet = new OctetString($c3Hex);
        $c2Octet = new OctetString($c2Hex);
        $sequence = new Sequence($c1xInt, $c1yInt, $c3Octet, $c2Octet);
        return strtoupper(bin2hex($sequence->getBinary()));
    }

    private function hexToDecimal(string $hex): string
    {
        if (extension_loaded('gmp')) {
            return gmp_strval(gmp_init($hex, 16), 10);
        }
        if (extension_loaded('bcmath')) {
            $decimal = '0';
            $len = strlen($hex);
            for ($i = 0; $i < $len; $i++) {
                $digit = hexdec($hex[$i]);
                $decimal = bcmul($decimal, '16', 0);
                $decimal = bcadd($decimal, (string)$digit, 0);
            }
            return $decimal;
        }
        throw new Exception('需要 gmp 或 bcmath 扩展来处理大整数');
    }

    private function debug(string $message, array $context = []): void
    {
        if ($this->logger instanceof LoggerInterface) {
            $this->logger->debug($message, $context);
        }
    }
}


