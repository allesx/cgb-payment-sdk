# 安装指南

## 快速安装

### Hyperf 框架项目

```bash
# 1. 安装依赖
composer require allesx/cgb-payment-sdk

# 2. 发布配置文件（可选）
php bin/hyperf.php vendor:publish allesx/cgb-payment-sdk cgb-config

# 3. 配置环境变量
# 编辑 .env 文件，添加 CGB 相关配置
```

### 其他 PHP 项目

```bash
# 1. 安装依赖
composer require allesx/cgb-payment-sdk

# 2. 手动创建配置文件
# 复制 config/autoload/cgb.php 到项目的配置目录

# 3. 配置环境变量
# 参考 .env.example 文件
```

## 配置步骤

### 1. 环境变量配置

在项目根目录的 `.env` 文件中添加以下配置：

```env
# 基础配置（必填）
CGB_APP_ID=your_app_id
CGB_ENT_CST_NO=your_ent_cst_no
CGB_ENT_USER_ID=your_ent_user_id
CGB_ENT_PASSWORD=your_password
CGB_GATEWAY_URL=https://ebank-yd03.test.cgbchina.com.cn:49081/deib/E1DEIB/E101/

# 证书配置（必填）
CGB_PRIVATE_KEY=data/cert/merchant.pfx
CGB_PRIVATE_KEY_PASS=your_key_pass
CGB_BANK_PUBLIC_KEY=data/cert/bank.cer

# 可选配置
CGB_PSW_ENC_PUB=your_sm2_public_key_hex
CGB_SIGN_ALGO=SHA1
CGB_TIMEOUT=30
```

### 2. 配置文件

对于 Hyperf 框架，配置文件会自动加载：`config/autoload/cgb.php`

对于其他框架，需要手动加载配置：

```php
$config = require 'path/to/cgb.php';
$client = new \Allesx\CgbPayment\Client\CgbClient($config);
```

### 3. 证书文件

将证书文件放到指定位置：

```
项目根目录/
├── data/
│   └── cert/
│       ├── merchant.pfx    # 商户私钥证书
│       └── bank.cer        # 银行公钥证书
└── .env                    # 环境变量配置
```

或使用绝对路径：

```env
CGB_PRIVATE_KEY=/absolute/path/to/merchant.pfx
CGB_BANK_PUBLIC_KEY=/absolute/path/to/bank.cer
```

## 验证安装

### Hyperf 框架

```php
use Allesx\CgbPayment\Client\CgbClient;
use Hyperf\HttpServer\Annotation\Controller;

#[Controller]
class TestController
{
    public function __construct(
        private CgbClient $cgbClient
    ) {}
    
    public function test()
    {
        // 测试账户查询
        $result = $this->cgbClient->request('0001', [
            'account' => '9550880401293700128',
            'ccyType' => '156',
        ]);
        
        return $result;
    }
}
```

### 其他框架

```php
require 'vendor/autoload.php';

use Allesx\CgbPayment\Client\CgbClient;

// 从配置文件加载
$config = require 'config/cgb.php';
$client = new CgbClient($config);

// 测试
$result = $client->request('0001', [
    'account' => '9550880401293700128',
    'ccyType' => '156',
]);

var_dump($result);
```

## 故障排查

### 1. 配置文件未找到

确保配置文件已正确创建：
- Hyperf: `config/autoload/cgb.php`
- 其他框架: 根据框架规范放置配置文件

### 2. 环境变量未加载

检查：
- `.env` 文件是否存在
- 环境变量名称是否正确（注意大小写）
- 是否使用了框架的环境变量加载机制

### 3. 证书路径错误

检查：
- 证书文件是否存在
- 路径是绝对路径还是相对路径
- 相对路径是否正确（相对于项目根目录）

### 4. 依赖注入失败（Hyperf）

确保：
- `composer.json` 中的 `extra.hyperf.config` 已正确配置
- 运行了 `composer dump-autoload -o`
- 清除了容器缓存：`rm -rf runtime/container`

## 📚 更多信息

- [Hyperf 集成指南](./HYPERF_INTEGRATION.md)
- [README.md](./README.md)
- [示例代码](./examples/)

