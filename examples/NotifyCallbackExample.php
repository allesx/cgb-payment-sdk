<?php

declare(strict_types=1);

/**
 * CGB 回调处理示例
 * 对应 Java SDK 的 CgbToErpTest
 * 
 * 功能：处理银行发送的异步通知（回调）
 * 流程：
 * 1. 接收银行请求（HTTP 头：encryptKey, signature, appId；请求体：加密的 HEX 字符串）
 * 2. 解密请求体（使用商户私钥解密 encryptKey 得到 SM4 密钥，再用 SM4 解密请求体）
 * 3. 验签（使用银行公钥验证 signature）
 * 4. 处理业务逻辑
 * 5. 生成响应（签名+加密）
 * 6. 返回加密响应给银行
 */

require_once __DIR__ . '/../autoload.php';

use Allesx\CgbPayment\Client\CgbClient;
use Allesx\CgbPayment\Exception\PayException;
use Psr\Log\NullLogger;

// 配置信息（与实际回调场景一致）
$config = [
    'app_id' => '907kbk2aogw2',
    'ent_cst_no' => '60000007905',
    'gateway_url' => 'https://ebank-yd03.test.cgbchina.com.cn:49081/deib/E1DEIB/E101/',
    'version' => '2.0.0',
    'private_key' => __DIR__ . '/../cert/907kbk2aogw2.pfx',
    'private_key_pass' => '1234qwer',
    'public_key' => __DIR__ . '/../cert/z22nn1x3m6r4.cer',
    'sign_algo' => 'SHA1',
];

$client = new CgbClient($config, new NullLogger());

/**
 * 模拟银行回调请求
 * 实际场景中，这些数据来自 HTTP 请求
 */
$encryptedBodyHex = '7C4AFF5C6FA8076BA929D2B12488D63B19C722662DBE3248B6AC38653882E719F0B2CD22A52C767B201A3EB6C20379AE5A9A89A22C03A5575D9F65CE9E36F77773A44A4ADB99D7C86057E254CE128AD0C5EC74F51F6FF6D7EF1B63EE5CB4957CF89DC57CDAE2A1F7F9A70584206F1B7BADDE396B8EE6846CCA5EB0F2302A9AF0D962BB7541709B572327083AB9BF6CDB6722D6D2D66E2EF1573CDDCBC9C74317F9955DAB591F623864D79AA093C4D16CD6F58F87F0940FC1D67472B72E20167DE31AC2601626E9EA69A0F9CE9D945A566C7FFB3FD101D1391C1C528CC356FD3C7F8A89D85D8FBF6F275BD4A3078084D83DBD352E0695F170B759E9047A2CEB0B0AABB6F1C5F0C60A81A255E7B3BAA3A9EC24A11AC0E0570C33998EF55FBD5C4DC73B20A7686F4E8A157E6A28EA8D05905613F693AF634A7E0A21A8B51BFC9DDD1885BE631E6C4A784F12842DADB19EBB96697E5752F5B07FCB9F2C3054D61E5D76CFE819EB5AEF848D31B54186DF2286F21FC8938BD641D6CDABC230A77BD1C3283309A82F4C327C5C71883846A4AD89EB1C637B0A295952EBC7757694E2A687E1A7712E8F30C1E27D24E40E9D77404595CE875E031AF4AFA2AF324E0EAA3729159A4626D7C2C9FEB59194B1987E703CBAA014B97825A27054B33EBED5963099EF7A5B2CD91869F3F4F051D7BC640CC869D8DDBDD235B5F39EE8F3B42B9F5C46AC4CD14268688CB2EA81232769D1726C3B0E6F9ACEF5B7648609D01342D4E0AB01678323CE6DF658B873E1AB23294B57242FEAF85DE42EFBB9C98819A6D0BEBF8450040E54FB6D7115FBC7E43A324750966F99CE7B142AD6074B07D2F09632C5993D337CD506A4B536690DA57DB47E9C7D56C804A0965313ADB738A46F4543C02C52CA6771E5DFA3F2AF159D2E9DAAD1360C0232B9181EE8A73742A28E09147A6E853EEC42DC7CFC1744F4D56C6F8B1917E172CB3EA1C2C2BF0C9CB20501F096C58613DC06CE88BDBE0D32B63324150E1CD2CDA50F1881FC0B2F833FA7D2D1DB960C4DB20D661F6844F57FA86080FA5F830339E432E7115DD21109F06FFBC47030331A2FF2086614B7A137BCD919A15097B73CAE76203ED7DA9079DEDB0D8F309697405BEFEAD90973346C1DD0B6D3782DBC8D5C1F8CE32978F211E895731F2985D4330D418576741A837E922DC039F74EBFE2B7E6D436F588F519096A7904889EEF0BF9DE43FC225670BC322BAC52FBAD25586D6B0E89DB4938B661D853024E19C0AEC1A53DEFDA444111F652E5EA7FFB2ED32E1424FDBAE28E51BCC6C1CAA3B4F2EF65F6A2AFADAE0D5163D311AA7A069EB730FCF90C8AFE7BA2E45353B1BB7BB14E5FA33436F171C299415AA4D9A424D61E3B547AC641E85D5D0028FBAD1764F254F1038B5BBF4CA77F2BEDBD6884F196EDBFA1BFEC1651811770B9945BE035FFABC4C2D812CE95A7B0E706906340';
$encryptKey = 'vgemsw9n9w4G7u312fChtLJVCY3jN/hg7uYk5qEcV9z+D3g97ZcWKQNt+XaDLXeipXfFirz89xY2iURkJXcfEAP/VB5A/GZHY18eLPPiXkPKtSnp2ouTxUkrVlDVWMmyvGCSoKVe4TPHWk+B5Q1begsgTlv96/WQ/3egR+dDM1tXFR824l9rxDSnTn8m3q3xO0qPrgr/MT2PJIgzJfNGNpY54ZbaeD2xCLxsYnfes+KB9NFwLNHi7TqNf5iz+IxPc0VjaSfnzCHfiw9NiPa3YHxtlleAl0/Fo2g5fEGRAKmczft2ab61TeXPDs7qUhMlp8qucbOayf6cJcxijPEdKg==';
$signature = 'VFn4MiqxLt7zCt3WHHfkVIqV4XITaIy73MY2zj04ctVAUrXxZq9FsFkZ8e3lID8ed2Rm+J0qVhG4l3rPq6gGCWnkCG2tvMmRNQ7+cBPu+bdn5wbtKcg3reoNF1ON6fdvas17JJ0+ljcAbUpeltUefGQ7sr2uspOHzvK8oaPnE9xFCoLiGNuG7B4GS+54sVcM0tYJSkk16cRrLakCQnzeONoi4WDwhfcsHuP0FE4fFwvHSZ5mrh9aXCTdGqCQTbIF+MRYEi7ZpcVEOZ8vGitqHlnJgY0u6mG/w+AlFsbSGZlqqSFxTZa64c2J3bRK1k2Mh3EekKHBnV/izM3zxQWbMA==';

echo "=== CGB 回调处理示例 ===\n";
echo "接收银行回调请求\n";
echo "encryptKey: " . substr($encryptKey, 0, 50) . "...\n";
echo "signature: " . substr($signature, 0, 50) . "...\n";
echo "encryptedBody (HEX): " . substr($encryptedBodyHex, 0, 100) . "...\n\n";

try {
    // 步骤1: 解密请求体
    echo "步骤1: 解密请求体...\n";
    $decryptResult = $client->processResponseDecryption($encryptKey, $signature, $encryptedBodyHex);
    
    if (empty($decryptResult['decrypted'])) {
        throw new PayException('解密失败: ' . ($decryptResult['decrypt_error'] ?? '未知错误'));
    }
    
    $plainRequest = $decryptResult['decrypted'];
    echo "解密成功！\n";
    echo "明文请求：\n" . $plainRequest . "\n\n";
    
    // 解析 JSON
    $requestData = json_decode($plainRequest, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new PayException('JSON 解析失败: ' . json_last_error_msg());
    }
    
    // 步骤2: 验签（processResponseDecryption 内部已验签）
    echo "步骤2: 验证签名...\n";
    $verifyResult = $decryptResult['verify_result'] ?? false;
    if (!$verifyResult) {
        echo "警告：验签失败，但继续处理\n";
        if (!empty($decryptResult['decryptError'])) {
            echo "错误信息：{$decryptResult['decryptError']}\n";
        }
    } else {
        echo "验签成功！\n\n";
    }
    
    // 步骤3: 处理业务逻辑
    echo "步骤3: 处理业务逻辑...\n";
    $header = $requestData['Header'] ?? [];
    $body = $requestData['Body'] ?? [];
    $tradeCode = $header['tradeCode'] ?? '';
    $seqNo = $header['seqNo'] ?? '';
    
    echo "交易码：{$tradeCode}\n";
    echo "流水号：{$seqNo}\n";
    echo "业务数据：" . json_encode($body, JSON_UNESCAPED_UNICODE) . "\n\n";
    
    /*---------------------------------------------------------------------------------------------*/
    /*--------------------------------------商户内部业务逻辑处理-------------------------------------*/
    /*---------------------------------------------------------------------------------------------*/
    
    // 步骤4: 生成响应报文
    echo "步骤4: 生成响应报文...\n";
    $now = new \DateTimeImmutable('now');
    $responseBody = [
        'Body' => [
            'bizRetInfo' => '动账通知成功',
            'bizRetCode' => '000000',
        ],
        'Header' => [
            'retSeqNo' => 'DEI1642132705115914240',
            'tranTime' => $now->format('His'),
            'seqNo' => $seqNo,
            'entCstNo' => $config['ent_cst_no'],
            'appId' => $config['app_id'],
            'sysRetInfo' => '通讯成功',
            'tradeCode' => $tradeCode,
            'sysRetCode' => '000000',
            'tranDate' => $now->format('Ymd'),
            'resdFlag' => 'N',
        ],
    ];
    
    $responseJson = json_encode($responseBody, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    echo "响应明文：\n" . $responseJson . "\n\n";
    
    // 步骤5: 签名响应
    echo "步骤5: 签名响应...\n";
    $responseSignature = $client->generateSignature($responseJson);
    echo "响应签名：{$responseSignature}\n\n";
    
    // 步骤6: 加密响应体
    echo "步骤6: 加密响应体...\n";
    $sm4Key = $client->generateSecretKey();
    $encryptedResponse = $client->encryptContentWithSecretKey($responseJson, $sm4Key);
    echo "加密后的响应体 (HEX)：\n" . $encryptedResponse . "\n\n";
    
    // 步骤7: 加密对称密钥
    echo "步骤7: 加密对称密钥...\n";
    $responseEncryptKey = $client->encryptSecretKey($sm4Key);
    echo "加密后的对称密钥 (Base64)：\n" . $responseEncryptKey . "\n\n";
    
    // 步骤8: 返回给银行（实际场景中，将以下内容放入 HTTP 响应）
    echo "=== 返回给银行的 HTTP 响应 ===\n";
    echo "HTTP 响应头：\n";
    echo "  signature: {$responseSignature}\n";
    echo "  appId: {$config['app_id']}\n";
    echo "  encryptKey: {$responseEncryptKey}\n";
    echo "  Content-Type: text/plain; charset=UTF-8\n";
    echo "\nHTTP 响应体（加密的 HEX 字符串）：\n";
    echo $encryptedResponse . "\n";
    
} catch (PayException $e) {
    echo "错误：" . $e->getMessage() . "\n";
} catch (\Exception $e) {
    echo "异常：" . $e->getMessage() . "\n";
    echo "文件：" . $e->getFile() . ":" . $e->getLine() . "\n";
}

