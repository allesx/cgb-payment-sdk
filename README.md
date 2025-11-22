# CGB Payment SDK (PHP)

广发银行（CGB）银企直联支付 SDK。支持请求签名（RSA-SHA1/SHA256）、SM4 对称加解密、银行公钥加密密钥、响应验签与解密、操作员密码 SM2 信封生成（可选）。

## 安装

Packagist（建议）：
```bash
composer require allesx/cgb-payment-sdk
```

Monorepo（本仓库内 path 依赖）：
```bash
composer update allesx/cgb-payment-sdk
```

## 快速开始
```php
use Allesx\CgbPayment\Client\CgbClient;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;

$config = [
    'app_id' => '907kbk2aogw2',
    'ent_cst_no' => '60000007905',
    'ent_user_id' => '100001',
    'ent_password' => '1q2w3e4r',
    'gateway_url' => 'https://ebank-yd03.test.cgbchina.com.cn:49081/deib/E1DEIB/E101/',
    'version' => '2.0.0',
    'private_key' => __DIR__ . '/data/cert/merchant.pfx',         // 或 PEM 字符串
    'private_key_pass' => 'your_password',
    'public_key' => __DIR__ . '/data/cert/bank.cer',              // 银行公钥证书
    'bank_psw_enc_pub' => 'SM2_PUBLIC_KEY_HEX',                   // 可选：操作员密码加密公钥
    'sign_algo' => 'SHA1',                                        // 或 SHA256
    'timeout' => 30,
    'mac_address' => '',                                          // 可选：固定上送
];

$logger = new Logger('cgb');
$logger->pushHandler(new StreamHandler(__DIR__ . '/cgb.log'));

$client = new CgbClient($config, $logger);

// 示例：交易码 0021（行内/行外付款）
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
var_dump($res['parsed'] ?? $res);
```

## 配置项
- app_id: 平台分配的 appId
- ent_cst_no: 企业客户号
- ent_user_id: 企业操作员
- ent_password: 操作员密码（生成密码信封）
- gateway_url: 银行网关地址（以 E101/ 结尾）
- version: 协议版本（默认 2.0.0）
- private_key: 商户私钥（PFX/PKCS12 文件路径或 PEM 字符串）
- private_key_pass: 私钥密码
- public_key: 银行公钥证书（.cer 或 PEM）
- bank_psw_enc_pub: 银行下发的“操作员密码加密公钥”（16进制 SM2 公钥），可选
- sign_algo: SHA1 或 SHA256
- timeout: 请求超时秒数
- mac_address: 覆盖上送 MAC（可选）

## 特性
- 请求签名：与银行侧保持一致的「先哈希，再十六进制字符串签名」
- 对称加解密：默认 SM4-ECB，兼容多种响应密文格式尝试解密
- 密钥加密/解密：使用银行公钥加密对称密钥、商户私钥解密
- 响应验签：与请求签名一致的验签流程，支持 SHA1 回退
- 操作员密码信封：使用 SM2 公钥生成 DER-HEX 格式，前缀 20 个 '='

## 测试
```bash
composer install
vendor/bin/phpunit -c packages/cgb-payment-sdk/phpunit.xml.dist
```

## 许可
MIT


