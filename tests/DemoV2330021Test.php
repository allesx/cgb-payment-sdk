<?php

declare(strict_types=1);

namespace Allesx\CgbPayment\Tests;

use Allesx\CgbPayment\Client\CgbClient;
use PHPUnit\Framework\TestCase;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Client as GuzzleClient;

class DemoV2330021Test extends TestCase
{
    private function generateRsaKeypair(): array
    {
        $config = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        $res = openssl_pkey_new($config);
        $priv = '';
        openssl_pkey_export($res, $priv);
        $pubDetails = openssl_pkey_get_details($res);
        $pub = $pubDetails['key'];
        return [$priv, $pub];
    }

    public function testDemo0021DecryptAndVerify(): void
    {
        // 1) 生成测试用 RSA 密钥对（充当商户私钥 / 银行公钥）
        [$privatePem, $publicPem] = $this->generateRsaKeypair();

        // 2) 构造 SDK 配置
        $config = [
            'app_id' => 'app',
            'ent_cst_no' => 'cst',
            'ent_user_id' => 'user',
            'ent_password' => 'pwd123456',
            'gateway_url' => 'https://example.org/deib/E1DEIB/E101/',
            'version' => '2.0.0',
            'private_key' => $privatePem,
            'private_key_pass' => '666',
            'public_key' => $publicPem, // loadBankPublicKey 可直接识别 PEM 公钥
            'sign_algo' => 'SHA1',
            'timeout' => 5,
        ];

        // 3) 使用真实的 SDK 方法生成一个“响应明文”，并签名、对称加密、再用公钥加密对称密钥
        $clientForBuild = new CgbClient($config);
        $plain = json_encode([
            'Header' => [
                'retCode' => '000000',
                'retMsg' => '成功',
                'retSeqNo' => 'RSEQ123456',
            ],
            'Body' => [
                'amount' => '1707.50',
                'attach' => ['demo' => 'ok'],
            ],
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        // 对称密钥（响应密钥）
        $respKey = random_bytes(16);
        // 使用 SDK 的加密实现生成密文（ECB HEX）
        $encryptedBodyHex = $clientForBuild->encryptContentWithSecretKey($plain, $respKey);
        // 用公钥加密对称密钥 -> Base64
        $encryptedKeyB64 = $clientForBuild->encryptSecretKey($respKey);
        // 对明文进行签名 -> Base64
        $signatureB64 = $clientForBuild->generateSignature($plain);

        // 4) 构造 Guzzle Mock 响应（模拟银行返回）
        $mock = new MockHandler([
            new Response(
                200,
                [
                    'encryptKey' => $encryptedKeyB64,
                    'signature' => $signatureB64,
                    'Content-Type' => 'text/plain; charset=UTF-8',
                ],
                $encryptedBodyHex // 响应体使用 HEX 密文
            ),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $httpClient = new GuzzleClient(['handler' => $handlerStack]);
        $config['http_client'] = $httpClient;

        // 5) 使用注入的 http_client 发起请求，SDK 会解密并验签
        $client = new CgbClient($config);
        $body = [
            'tradeTypeNo' => 'AC0ZA001',
            'entBizDt' => '20240718',
            'entBizId' => '202407180021091902001',
            'entCstNo' => '60000007905',
            'payerAcctNo' => '100001',
            'payerAcctName' => '测试公司',
            'remark' => '备注',
            'payeeAcctNo' => '1111222233334444',
            'payeeAcctName' => '收款公司',
            'payeeBkFlag' => 'T',
            'payeeBkNo' => '307100003019',
            'payeeBkName' => '平安银行股份有限公司北京分行',
            'amount' => '1707.50',
            'postscript' => '附言',
            'addWord' => '11',
            'acBkShowFlag' => '',
        ];
        $res = $client->request('0021', $body);

        // 6) 断言解析结果
        $this->assertSame('success', $res['status']);
        $this->assertArrayHasKey('parsed', $res);
        $this->assertIsArray($res['parsed']);
        $this->assertSame('000000', $res['parsed']['Header']['retCode']);
        $this->assertSame('1707.50', $res['parsed']['Body']['amount']);
        $this->assertNull($res['decrypt_error'] ?? null);
    }
}


