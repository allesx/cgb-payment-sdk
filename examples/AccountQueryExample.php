<?php

declare(strict_types=1);

/**
 * E1010001 - 账户查询示例
 * 对应 Java SDK 的 E1010001Test
 * 
 * 交易码：0001
 * 功能：查询账户余额等信息
 */

require_once __DIR__ . '/../autoload.php';

use Allesx\CgbPayment\Client\CgbClient;
use Psr\Log\NullLogger;

// 配置信息（从配置文件或环境变量读取）
$config = [
    'app_id' => '907kbk2aogw2',
    'ent_cst_no' => '60000007905',
    'ent_user_id' => '100001',
    'ent_password' => '1q2w3e4r',
    'gateway_url' => 'https://ebank-yd03.test.cgbchina.com.cn:49081/deib/E1DEIB/E101/',
    'version' => '2.0.0',
    'private_key' => __DIR__ . '/../cert/907kbk2aogw2.pfx',
    'private_key_pass' => '1234qwer',
    'public_key' => __DIR__ . '/../cert/z22nn1x3m6r4.cer',
    'sign_algo' => 'SHA1',
    'timeout' => 30,
];

// 创建客户端（使用空日志，生产环境建议使用真实 Logger）
$client = new CgbClient($config, new NullLogger());

// 方式1：使用数组构造请求体
$body = [
    'account' => '9550880401293700128',  // 账户号
    'ccyType' => '156',                  // 币种类型（156=人民币）
];

echo "=== E1010001 账户查询示例 ===\n";
echo "交易码：0001\n";
echo "请求体：" . json_encode($body, JSON_UNESCAPED_UNICODE) . "\n\n";

try {
    // 发送请求
    $result = $client->request('0001', $body);
    
    // 检查结果
    if (!empty($result['parsed'])) {
        $parsed = $result['parsed'];
        $header = $parsed['Header'] ?? [];
        $responseBody = $parsed['Body'] ?? [];
        
        echo "请求成功！\n";
        echo "返回码：{$header['retCode']}\n";
        echo "返回信息：{$header['retMsg']}\n";
        echo "流水号：{$header['retSeqNo']}\n";
        echo "\n账户信息：\n";
        echo json_encode($responseBody, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n";
    } else {
        echo "请求失败或解密失败\n";
        if (!empty($result['decrypt_error'])) {
            echo "错误信息：{$result['decrypt_error']}\n";
        }
        echo "原始响应：" . ($result['raw'] ?? '') . "\n";
    }
} catch (\Exception $e) {
    echo "异常：" . $e->getMessage() . "\n";
    echo "文件：" . $e->getFile() . ":" . $e->getLine() . "\n";
}

