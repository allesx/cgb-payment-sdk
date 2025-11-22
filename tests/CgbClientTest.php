<?php

declare(strict_types=1);

namespace Allesx\CgbPayment\Tests;

use Allesx\CgbPayment\Client\CgbClient;
use Allesx\CgbPayment\Exception\PayException;
use PHPUnit\Framework\TestCase;

class CgbClientTest extends TestCase
{
    private function validConfig(): array
    {
        return [
            'app_id' => 'app',
            'ent_cst_no' => 'cst',
            'ent_user_id' => 'user',
            'ent_password' => 'pwd123456',
            'gateway_url' => 'https://example.org/deib/E1DEIB/E101/',
            'version' => '2.0.0',
            // 使用无效的占位内容，避免依赖真实证书；构造时不触发读取
            'private_key' => '-----BEGIN PRIVATE KEY-----MIIB...FAKE-----END PRIVATE KEY-----',
            'private_key_pass' => '666',
            'public_key' => '-----BEGIN CERTIFICATE-----MIIB...FAKE-----END CERTIFICATE-----',
            'sign_algo' => 'SHA1',
            'timeout' => 5,
        ];
    }

    public function testGenerateSecretKeyLength(): void
    {
        $client = new CgbClient($this->validConfig());
        $key = $client->generateSecretKey();
        $this->assertSame(16, strlen($key));
    }

    public function testValidateConfigMissing(): void
    {
        $this->expectException(PayException::class);
        new CgbClient([]);
    }
}


