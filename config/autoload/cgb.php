<?php

declare(strict_types=1);

/**
 * 广发银行 CGB 支付 SDK 配置文件
 * 适用于 Hyperf 框架
 * 
 * 此配置文件会自动从环境变量读取配置值
 * 环境变量配置示例请参考 .env.example 文件
 * 
 * 使用方式：
 * 1. 在项目根目录的 .env 文件中配置环境变量
 * 2. 在代码中通过 ConfigInterface::get('cgb') 获取配置
 * 3. 或者直接注入 CgbClient 使用
 */

return [
    // ========================================
    // 基础配置（必填）
    // ========================================
    
    // 平台分配的 appId
    'app_id' => env('CGB_APP_ID', ''),
    
    // 企业客户号
    'ent_cst_no' => env('CGB_ENT_CST_NO', ''),
    
    // 企业操作员ID
    'ent_user_id' => env('CGB_ENT_USER_ID', ''),
    
    // 操作员密码（明文）
    'ent_password' => env('CGB_ENT_PASSWORD', ''),
    
    // 银行网关地址
    'gateway_url' => env('CGB_GATEWAY_URL', 'https://ebank-yd03.test.cgbchina.com.cn:49081/deib/E1DEIB/E101/'),
    
    // 协议版本
    'version' => env('CGB_VERSION', '2.0.0'),
    
    // ========================================
    // 证书配置（必填）
    // ========================================
    
    // 商户私钥证书路径（PFX/PKCS12 格式）
    // 支持绝对路径或相对路径（相对于项目根目录）
    // 如果路径是相对路径，会基于 BASE_PATH 解析
    'private_key' => env('CGB_PRIVATE_KEY', ''),
    
    // 私钥密码（如果 PFX 有密码，填写密码；如果没有，留空）
    // 注意：键必须存在，可为空字符串（PEM 或无口令PFX）
    'private_key_pass' => env('CGB_PRIVATE_KEY_PASS', ''),
    
    // 银行公钥证书路径（.cer 格式）
    // 支持绝对路径或相对路径（相对于项目根目录）
    // 如果路径是相对路径，会基于 BASE_PATH 解析
    'public_key' => env('CGB_BANK_PUBLIC_KEY', ''),
    
    // ========================================
    // 可选配置
    // ========================================
    
    // 操作员密码加密公钥（SM2公钥HEX字符串，130位）
    // 如果配置了此项，操作员密码将使用SM2加密生成密码信封
    // 如果不配置或留空，将使用明文密码
    'bank_psw_enc_pub' => env('CGB_PSW_ENC_PUB', ''),
    
    // 签名算法（SHA1 或 SHA256）
    // 默认使用 SHA1（与银行侧保持一致）
    'sign_algo' => env('CGB_SIGN_ALGO', 'SHA1'),
    
    // 加密算法类型（RSA 或 SM2）
    // 默认使用 RSA
    'cryption_algorithm' => env('CGB_ENCRYPT_TYPE', 'RSA'),
    
    // 固定MAC地址（可选）
    // 如果不配置，SDK会自动获取系统MAC地址
    // 如果需要固定值，可以配置此项
    'mac_address' => env('CGB_MAC_ADDRESS', ''),
    
    // HTTP请求超时时间（秒）
    'timeout' => (int) env('CGB_TIMEOUT', 30),
    
    // Debug 日志开关（可选）
    // true: 输出所有 debug 日志（包括请求体、响应体等详细信息）
    // false: 不输出 debug 日志（默认，生产环境建议关闭）
    // 可通过环境变量 CGB_DEBUG 配置
    'debug' => (bool) env('CGB_DEBUG', false),
];

