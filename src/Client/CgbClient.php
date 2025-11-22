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

/**
 * CGB 支付客户端
 * 广发银行银企直联支付 SDK 的核心客户端类
 * 提供完整的请求签名、加密、发送、解密、验签功能
 * 
 * 对应 Java SDK 的 RequestSender 和 SecurityManager 的组合功能
 */
class CgbClient
{
    private array $config;
    
    /** @var LoggerInterface|null 日志记录器 */
    private ?LoggerInterface $logger;

    /**
     * 构造函数
     * 
     * @param array $config 配置数组，包含以下必需项：
     *   - app_id: 平台分配的 appId
     *   - ent_cst_no: 企业客户号
     *   - ent_user_id: 企业操作员
     *   - ent_password: 操作员密码
     *   - gateway_url: 银行网关地址
     *   - private_key: 商户私钥文件路径或PEM字符串
     *   - private_key_pass: 私钥密码
     *   - public_key: 银行公钥证书文件路径或PEM字符串
     *   - version: 协议版本（可选，默认2.0.0）
     *   - sign_algo: 签名算法（可选，默认SHA1）
     *   - timeout: 请求超时秒数（可选，默认30）
     *   - bank_psw_enc_pub: 操作员密码加密公钥（可选，SM2公钥HEX）
     *   - mac_address: 固定MAC地址（可选）
     *   - http_client: 自定义Guzzle客户端（可选，用于测试）
     * @param LoggerInterface|null $logger 日志记录器（可选）
     * @throws PayException 配置验证失败时抛出
     */
    public function __construct(array $config, ?LoggerInterface $logger = null)
    {
        $this->config = $config;
        $this->logger = $logger;
        $this->validateConfig();
    }
    
    /**
     * 验证配置参数
     * 检查必需配置项是否存在，设置默认值
     * 
     * @return void
     * @throws PayException 缺少必需配置项时抛出
     */
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

    /**
     * 发送请求（便捷方法）
     * 
     * @param string $tradeCode 交易码（如 '0001', '0021'）
     * @param array $body 请求体数据
     * @return array 响应结果，包含：
     *   - status: 请求状态
     *   - headers: 响应头
     *   - raw: 原始响应体
     *   - decrypted: 解密后的明文
     *   - parsed: 解析后的JSON数组
     *   - decrypt_error: 解密错误信息（如有）
     * @throws PayException 请求失败时抛出
     */
    public function request(string $tradeCode, array $body): array
    {
        return $this->sendCompleteRequest($body, $tradeCode);
    }

    /**
     * 发送完整请求
     * 执行完整的请求流程：构建请求、签名、加密、发送、解密、验签
     * 对应 Java SDK 的 RequestSender.send
     * 
     * @param array $requestBody 请求体数据（Body部分）
     * @param string $tradeCode 交易码（如 '0001', '0021'）
     * @return array 响应结果，包含：
     *   - status: 请求状态（'success' 或 'failed'）
     *   - headers: 响应头数组
     *   - raw: 原始响应体（加密的）
     *   - decrypted: 解密后的明文
     *   - parsed: 解析后的JSON数组，失败时为null
     *   - decrypt_error: 解密错误信息，成功时为null
     * @throws PayException 请求失败时抛出
     */
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
            $this->debug('CGB:STEP8:decrypt', ['decrypt' => $decrypt]);

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

    /**
     * 处理响应解密和解析（可用于回调处理）
     * 
     * @param string $respEncryptKey 响应头中的encryptKey（Base64编码的加密对称密钥）
     * @param string $respSignature 响应头中的signature（签名）
     * @param string $respBodyRaw 响应体原始数据（加密的）
     * @return array 返回包含以下键的数组：
     *   - 'decrypted': string 解密后的明文
     *   - 'parsed': array|null 解析后的JSON数组，失败时为null
     *   - 'decrypt_error': string|null 错误信息，成功时为null
     *   - 'verify_result': bool 验签结果
     */
    public function processResponseDecryption(string $respEncryptKey, string $respSignature, string $respBodyRaw): array
    {
        $decrypted = '';
        $parsed = null;
        $decryptError = null;
        $verifyResult = false;

        try {
            $respKeyBytes = $this->decryptSecretKey($respEncryptKey);
            $decrypted = $this->decryptContentSmart($respBodyRaw, $respKeyBytes);
            if (empty($decrypted)) {
                $decryptError = '解密后的内容为空';
            } else {
                // 验签
                if (!empty($respSignature)) {
                    $verifyResult = $this->verifySignature($decrypted, $respSignature);
                    if (!$verifyResult) {
                        $decryptError = '响应验签失败';
                    }
                } else {
                    $decryptError = '响应头中缺少signature，跳过验签';
                }
                // JSON解析
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
            'verify_result' => $verifyResult,
        ];
    }

    /**
     * 发送HTTP请求
     * 使用 Guzzle HTTP 客户端发送POST请求
     * 
     * @param string $url 请求URL
     * @param array $headers HTTP头数组（格式：['key: value', ...]）
     * @param string $body 请求体（加密的HEX字符串）
     * @return array 响应结果，包含：
     *   - status: 状态（'success'）
     *   - body: 响应体
     *   - headers: 响应头数组
     *   - http_code: HTTP状态码
     * @throws PayException HTTP请求失败时抛出
     */
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

    /**
     * 生成签名
     * 使用RSA私钥对内容进行签名
     * 对应 Java SDK 的 SecurityManager.generateSignature
     * 
     * 签名流程：
     * 1. 对内容进行哈希（SHA1或SHA256）
     * 2. 将二进制哈希转换为小写十六进制字符串
     * 3. 对处理后的字符串进行RSA签名
     * 4. Base64编码签名结果
     * 
     * @param string $content 待签名内容
     * @return string Base64编码的签名
     * @throws PayException 签名失败时抛出
     */
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

    /**
     * 验证签名
     * 使用银行公钥验证签名
     * 对应 Java SDK 的 SecurityManager.verifySignature
     * 
     * 验签流程与签名流程一致：
     * 1. 对内容进行哈希（SHA1或SHA256）
     * 2. 将二进制哈希转换为小写十六进制字符串
     * 3. 对处理后的字符串进行RSA验签
     * 
     * 如果配置的算法不是SHA1且验签失败，会自动回退尝试SHA1（兼容银行历史实现）
     * 
     * @param string $content 原始内容
     * @param string $signatureB64 Base64编码的签名
     * @return bool 验签结果，true表示验证通过
     * @throws PayException 验签过程出错时抛出
     */
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

    /**
     * 生成对称密钥
     * 生成16字节（128位）的随机对称密钥，用于SM4加密
     * 对应 Java SDK 的 SecurityManager.generateSecretKey
     * 
     * @return string 16字节的二进制密钥
     * @throws PayException 生成失败时抛出
     */
    public function generateSecretKey(): string
    {
        try {
            return \random_bytes(16);
        } catch (Exception $e) {
            throw new PayException('生成密钥失败:' . $e->getMessage());
        }
    }

    /**
     * 加密对称密钥
     * 使用银行公钥对对称密钥进行RSA加密
     * 对应 Java SDK 的 SecurityManager.encryptSecretKey
     * 
     * @param string $secretKey 16字节的对称密钥
     * @return string Base64编码的加密密钥
     * @throws PayException 加密失败时抛出
     */
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

    /**
     * 解密对称密钥
     * 使用商户私钥解密银行返回的加密对称密钥
     * 对应 Java SDK 的 SecurityManager.decryptSecretKey
     * 
     * @param string $encryptKeyB64 Base64编码的加密密钥
     * @return string 16字节的对称密钥
     * @throws PayException 解密失败时抛出
     */
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

    /**
     * 使用对称密钥加密内容
     * 使用SM4-ECB模式加密内容
     * 对应 Java SDK 的 SecurityManager.encryptContentWithSecretKey
     * 
     * 加密流程：
     * 1. PKCS7填充内容到16字节的倍数
     * 2. 使用SM4-ECB模式加密
     * 3. 转换为大写十六进制字符串返回
     * 
     * @param string $content 待加密内容
     * @param string $secretKey 16字节的对称密钥
     * @return string 加密后的HEX字符串（大写）
     * @throws Exception 加密失败时抛出
     */
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

    /**
     * 智能解密内容
     * 自动识别加密格式（HEX或Base64），尝试多种解密方式
     * 对应 Java SDK 的 SecurityManager.decryptContentWithSecretKeyDirect
     * 
     * 解密策略：
     * 1. 优先尝试SM4-ECB解密
     * 2. 如果失败，尝试SM4-CBC（IV在最后或前面）
     * 3. 清理解密结果（去除BOM和控制字符）
     * 
     * @param string $encryptedContent 加密内容（HEX或Base64格式）
     * @param string $secretKey 16字节的对称密钥
     * @return string 解密后的明文，失败时返回空字符串
     */
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

    /**
     * 加载银行公钥
     * 支持 .cer 证书文件和 PEM 格式
     * 
     * @return \OpenSSLAsymmetricKey|resource OpenSSL公钥资源（PHP 8+ 返回 OpenSSLAsymmetricKey，PHP 7 返回 resource）
     * @throws PayException 加载失败时抛出
     */
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

    /**
     * 加载商户私钥
     * 支持 PFX/PKCS12 证书文件和 PEM 格式
     * 
     * @return \OpenSSLAsymmetricKey|\OpenSSLCertificate|resource OpenSSL私钥资源（PHP 8+ 返回 OpenSSLAsymmetricKey，PHP 7 返回 resource）
     * @throws PayException 加载失败时抛出
     */
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

    /**
     * 清理明文
     * 去除BOM和控制字符，便于JSON解析
     * 
     * @param string $str 原始字符串
     * @return string 清理后的字符串
     */
    private function cleanupPlaintext(string $str): string
    {
        $str = preg_replace('/^\xEF\xBB\xBF/', '', $str);
        $str = preg_replace('/[\x00-\x1F\x7F]/u', '', $str);
        return trim((string)$str);
    }

    /**
     * 生成操作员密码信封（如果可能）
     * 如果配置了 bank_psw_enc_pub，则使用SM2加密密码
     * 否则返回明文密码
     * 
     * @param string $plainPassword 明文密码
     * @return string 密码信封（格式：==================== + 大写HEX密文）或明文密码
     */
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

    /**
     * SM2加密操作员密码
     * 对应 Java SDK 的 SMUtil.sm2EncryptOperatorPwd
     * 
     * 加密流程：
     * 1. 处理长度前缀（len < 10 补0，len >= 100 返回 "888"）
     * 2. 使用SM2公钥加密
     * 3. 转换为DER格式
     * 4. 添加20个'='前缀
     * 
     * @param string $pubHex 公钥16进制字符串（130字符，64字节公钥）
     * @param string $operatorPwd 明文操作密码
     * @return string 加密后的字符串，格式：==================== + 大写HEX密文（DER格式）
     * @throws Exception 加密失败时抛出
     */
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

    /**
     * 将SM2加密的C1C3C2格式转换为DER格式
     * 对应 Java SDK 的 SM2Utils.encodeSM2CipherToDER
     * 
     * DER格式：SEQUENCE { INTEGER(c1x), INTEGER(c1y), OCTET STRING(c3), OCTET STRING(c2) }
     * 
     * @param string $c1c3c2Hex C1C3C2格式的HEX字符串
     * @return string DER格式的HEX字符串
     * @throws Exception 编码失败时抛出
     */
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

    /**
     * 十六进制转十进制
     * 支持GMP和BCMath扩展
     * 
     * @param string $hex 十六进制字符串
     * @return string 十进制字符串
     * @throws Exception GMP和BCMath都不可用时抛出
     */
    private function hexToDecimal(string $hex): string
    {
        if (extension_loaded('gmp')) {
            return \gmp_strval(\gmp_init($hex, 16), 10);
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

    /**
     * 获取配置数组
     * 
     * @return array 配置数组（只读副本）
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * 记录调试日志
     * 
     * @param string $message 日志消息
     * @param array $context 上下文数据
     * @return void
     */
    private function debug(string $message, array $context = []): void
    {
        if ($this->logger instanceof LoggerInterface) {
            $this->logger->debug($message, $context);
        }
    }
}


