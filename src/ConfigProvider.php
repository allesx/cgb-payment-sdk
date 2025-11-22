<?php

declare(strict_types=1);

namespace Allesx\CgbPayment;

/**
 * Hyperf 框架配置提供者
 * 用于自动注册 CGB 支付 SDK 的配置和服务
 * 
 * 此文件会被 Hyperf 框架自动发现和加载
 * 配置路径：config/autoload/cgb.php
 */
class ConfigProvider
{
    /**
     * 返回配置数组
     * 
     * @return array
     */
    public function __invoke(): array
    {
        return [
            // 配置合并到 config/autoload/cgb.php
            'dependencies' => [
                // 注册 CgbClient 的工厂方法
                \Allesx\CgbPayment\Client\CgbClient::class => \Allesx\CgbPayment\Client\CgbClientFactory::class,
            ],
            
            // 命令注册（如果有CLI命令）
            'commands' => [
                // 示例：\Allesx\CgbPayment\Command\TestCommand::class,
            ],
            
            // 监听器注册（如果有事件监听器）
            'listeners' => [
                // 示例：\Allesx\CgbPayment\Listener\PaymentListener::class,
            ],
            
            // 注解扫描路径
            'annotations' => [
                'scan' => [
                    'paths' => [
                        __DIR__,
                    ],
                ],
            ],
            
            // 发布配置文件的路径
            'publish' => [
                [
                    'id' => 'cgb-config',
                    'description' => 'CGB支付SDK配置文件',
                    'source' => __DIR__ . '/../config/autoload/cgb.php',
                    'destination' => BASE_PATH . '/config/autoload/cgb.php',
                ]
            ],
        ];
    }
}

