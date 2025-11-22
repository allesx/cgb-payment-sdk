# CGB Payment SDK 示例代码

本目录包含广发银行银企直联支付 SDK 的使用示例代码。

## 示例列表

### 1. AccountQueryExample.php - 账户查询示例（0001）

对应 Java SDK 的 `E1010001Test.java`

**功能**：查询账户余额等信息

**使用方式**：
```bash
php examples/AccountQueryExample.php
```

**说明**：
- 交易码：0001
- 请求参数：`account`（账户号）、`ccyType`（币种类型）
- 返回结果：账户余额、可用余额、冻结金额等信息

### 2. NotifyCallbackExample.php - 回调处理示例

对应 Java SDK 的 `CgbToErpTest.java`

**功能**：处理银行发送的异步通知（回调）

**使用方式**：
```bash
php examples/NotifyCallbackExample.php
```

**说明**：
- 演示如何接收和解密银行回调请求
- 演示如何验签
- 演示如何生成加密响应返回给银行

**流程**：
1. 接收银行请求（HTTP 头：encryptKey, signature, appId；请求体：加密的 HEX 字符串）
2. 解密请求体（使用商户私钥解密 encryptKey 得到 SM4 密钥，再用 SM4 解密请求体）
3. 验签（使用银行公钥验证 signature）
4. 处理业务逻辑
5. 生成响应（签名+加密）
6. 返回加密响应给银行

## 配置说明

示例中使用的是测试环境配置，生产环境需要：

1. 修改证书路径
   - `private_key`: 商户私钥证书路径
   - `public_key`: 银行公钥证书路径

2. 修改配置信息
   - `app_id`: 平台分配的 appId
   - `ent_cst_no`: 企业客户号
   - `ent_user_id`: 企业操作员
   - `ent_password`: 操作员密码
   - `gateway_url`: 银行网关地址（生产环境地址）

3. 确保证书文件存在
   - 示例中使用的证书路径是 `../cert/` 目录
   - 实际使用时请替换为你的证书路径

## 运行示例前准备

1. 安装依赖
```bash
composer install
```

2. 准备证书文件（可选，用于真实测试）
- 商户私钥证书（.pfx）
- 银行公钥证书（.cer）

3. 修改配置
- 编辑示例文件中的 `$config` 数组
- 或创建配置文件，在示例中加载

## 注意事项

1. **测试环境**：示例中使用的是广发银行测试环境地址
2. **证书路径**：请确保证书文件路径正确，或使用绝对路径
3. **日志**：示例中使用 `NullLogger`，生产环境建议使用真实 Logger（如 Monolog）
4. **错误处理**：实际使用时请添加完整的错误处理和日志记录

## 更多示例

- 付款示例（0021）：参见项目中的 `app/Controller/Payment/CgbController.php`
- 其他交易码示例：参考广发银行官方文档和 Java SDK Demo

