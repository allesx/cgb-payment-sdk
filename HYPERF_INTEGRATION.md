# Hyperf 框架集成指南

本文档说明如何在 Hyperf 框架中集成和使用 CGB 支付 SDK。

## 安装

### 1. 通过 Composer 安装

```bash
composer require allesx/cgb-payment-sdk
```

### 2. 发布配置文件

```bash
php bin/hyperf.php vendor:publish allesx/cgb-payment-sdk cgb-config
```

这会自动将配置文件复制到 `config/autoload/cgb.php`。

### 3. 配置环境变量

复制 `.env.example` 到项目根目录的 `.env` 文件，并修改配置：

```bash
cp vendor/allesx/cgb-payment-sdk/.env.example .env
```

或者手动在 `.env` 文件中添加配置项：

```env
CGB_APP_ID=your_app_id
CGB_ENT_CST_NO=your_ent_cst_no
CGB_ENT_USER_ID=your_ent_user_id
CGB_ENT_PASSWORD=your_password
CGB_GATEWAY_URL=https://ebank-yd03.test.cgbchina.com.cn:49081/deib/E1DEIB/E101/
CGB_PRIVATE_KEY=data/cert/merchant.pfx
CGB_PRIVATE_KEY_PASS=your_key_pass
CGB_BANK_PUBLIC_KEY=data/cert/bank.cer
CGB_PSW_ENC_PUB=your_sm2_public_key_hex
CGB_SIGN_ALGO=SHA1
CGB_TIMEOUT=30
```

## 使用方法

### 方式 1：依赖注入（推荐）

在控制器或服务类中，通过构造函数注入 `CgbClient`：

```php
<?php

namespace App\Controller\Payment;

use Allesx\CgbPayment\Client\CgbClient;
use Hyperf\HttpServer\Annotation\Controller;
use Hyperf\HttpServer\Annotation\PostMapping;

#[Controller(prefix: '/cgb')]
class CgbController
{
    public function __construct(
        private CgbClient $cgbClient
    ) {
    }
    
    #[PostMapping('/test0021')]
    public function test0021(): array
    {
        $body = [
            'tradeTypeNo' => 'AC0ZA001',
            'entBizDt' => date('Ymd'),
            'entBizId' => '202407180021091902001',
            'payerAcctNo' => '9550885327262700163',
            'payerAcctName' => '测试公司',
            'payeeAcctNo' => '6226221103210834',
            'payeeAcctName' => '收款人',
            'payeeBkFlag' => 'T',
            'payeeBkNo' => '305100000013',
            'payeeBkName' => '中国民生银行',
            'amount' => '1707.50',
            'remark' => '测试备注',
            'postscript' => '测试附言',
        ];
        
        $result = $this->cgbClient->request('0021', $body);
        
        return $result;
    }
}
```

### 方式 2：从容器获取

```php
use Allesx\CgbPayment\Client\CgbClient;
use Hyperf\Context\ApplicationContext;

$cgbClient = ApplicationContext::getContainer()->get(CgbClient::class);

$result = $cgbClient->request('0001', ['account' => '9550880401293700128', 'ccyType' => '156']);
```

### 方式 3：手动创建（不推荐）

如果不想使用依赖注入，也可以手动创建：

```php
use Allesx\CgbPayment\Client\CgbClient;
use Hyperf\Contract\ConfigInterface;
use Psr\Log\LoggerInterface;

$config = di(ConfigInterface::class)->get('cgb', []);
$logger = di(LoggerInterface::class); // 可选

$cgbClient = new CgbClient($config, $logger);
```

## 配置说明

### 环境变量配置

所有配置项都可以通过环境变量设置，在 `.env` 文件中配置：

| 环境变量               | 说明                      | 必填         | 默认值       |
| ---------------------- | ------------------------- | ------------ | ------------ |
| `CGB_APP_ID`           | 平台分配的 appId          | 是           | -            |
| `CGB_ENT_CST_NO`       | 企业客户号                | 是           | -            |
| `CGB_ENT_USER_ID`      | 企业操作员ID              | 是           | -            |
| `CGB_ENT_PASSWORD`     | 操作员密码                | 是           | -            |
| `CGB_GATEWAY_URL`      | 银行网关地址              | 是           | 测试环境地址 |
| `CGB_PRIVATE_KEY`      | 商户私钥证书路径          | 是           | -            |
| `CGB_PRIVATE_KEY_PASS` | 私钥密码                  | 是（可为空） | -            |
| `CGB_BANK_PUBLIC_KEY`  | 银行公钥证书路径          | 是           | -            |
| `CGB_PSW_ENC_PUB`      | 操作员密码加密公钥（SM2） | 否           | -            |
| `CGB_SIGN_ALGO`        | 签名算法                  | 否           | SHA1         |
| `CGB_ENCRYPT_TYPE`     | 加密算法类型              | 否           | RSA          |
| `CGB_MAC_ADDRESS`      | 固定MAC地址               | 否           | 自动获取     |
| `CGB_TIMEOUT`          | HTTP超时时间（秒）        | 否           | 30           |
| `CGB_VERSION`          | 协议版本                  | 否           | 2.0.0        |

### 路径配置说明

证书路径支持两种格式：

1. **绝对路径**：直接使用完整路径
   ```env
   CGB_PRIVATE_KEY=/data/cert/merchant.pfx
   ```

2. **相对路径**：相对于项目根目录（BASE_PATH）
   ```env
   CGB_PRIVATE_KEY=data/cert/merchant.pfx
   ```
   
   SDK 会自动将相对路径转换为绝对路径。

3. **PEM 字符串**：可以直接使用 PEM 格式的证书字符串（多行）
   ```env
   CGB_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
   ```

## 高级配置

### 自定义日志记录器

SDK 默认会尝试使用容器中的 `LoggerInterface` 实例。如果需要使用自定义日志记录器：

```php
use Allesx\CgbPayment\Client\CgbClient;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$logger = new Logger('cgb');
$logger->pushHandler(new StreamHandler(BASE_PATH . '/runtime/logs/cgb.log'));

$cgbClient = new CgbClient($config, $logger);
```

### 自定义 HTTP 客户端

用于测试时模拟 HTTP 响应：

```php
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;

$mock = new MockHandler([
    new Response(200, ['encryptKey' => '...', 'signature' => '...'], '...'),
]);
$handlerStack = HandlerStack::create($mock);
$httpClient = new GuzzleClient(['handler' => $handlerStack]);

$config['http_client'] = $httpClient;
$cgbClient = new CgbClient($config);
```

## 示例代码

### 账户查询（0001）

```php
$body = [
    'account' => '9550880401293700128',
    'ccyType' => '156', // 156=人民币
];

$result = $cgbClient->request('0001', $body);

if (!empty($result['parsed'])) {
    $data = $result['parsed']['Body'];
    echo "账户余额：" . ($data['balance'] ?? 'N/A') . "\n";
}
```

### 处理银行回调

```php
use Hyperf\HttpServer\Contract\RequestInterface;

// 在控制器中
public function notify(): array
{
    $request = di(RequestInterface::class);
    
    // 从 HTTP 请求获取
    $encryptKey = $request->header('encryptKey', '');
    $signature = $request->header('signature', '');
    $encryptedBody = $request->getBody()->getContents();
    
    // 解密和验签
    $result = $this->cgbClient->processResponseDecryption($encryptKey, $signature, $encryptedBody);
    
    if (!empty($result['parsed'])) {
        $requestData = $result['parsed'];
        // 处理业务逻辑...
        
        // 生成响应
        $responseJson = json_encode(['Body' => [...], 'Header' => [...]], JSON_UNESCAPED_UNICODE);
        $responseSignature = $this->cgbClient->generateSignature($responseJson);
        $sm4Key = $this->cgbClient->generateSecretKey();
        $encryptedResponse = $this->cgbClient->encryptContentWithSecretKey($responseJson, $sm4Key);
        $responseEncryptKey = $this->cgbClient->encryptSecretKey($sm4Key);
        
        // 返回给银行
        return response()
            ->withHeader('signature', $responseSignature)
            ->withHeader('appId', $config['app_id'])
            ->withHeader('encryptKey', $responseEncryptKey)
            ->withHeader('Content-Type', 'text/plain; charset=UTF-8')
            ->withBody(new \Hyperf\HttpMessage\Stream\SwooleStream($encryptedResponse));
    }
    
    return ['error' => '解密失败'];
}
```

## 故障排查

### 1. 配置文件未加载

确保配置文件已发布：
```bash
php bin/hyperf.php vendor:publish allesx/cgb-payment-sdk cgb-config
```

### 2. 路径解析错误

检查证书文件路径是否正确，可以使用绝对路径：
```env
CGB_PRIVATE_KEY=/absolute/path/to/cert.pfx
```

### 3. 依赖注入失败

确保 `ConfigProvider` 已正确注册。检查 `composer.json` 中的 `extra.hyperf.config` 是否正确。

## 更多信息

- [README.md](./README.md) - SDK 使用文档
- [示例代码](./examples/) - 更多使用示例
- [安装指南](./INSTALL.md) - 详细安装步骤

