<?php

declare(strict_types=1);

namespace Allesx\CgbPayment\Client;

use Hyperf\Contract\ConfigInterface;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * CgbClient 工厂类
 * 用于在 Hyperf 框架中自动创建和注入 CgbClient 实例
 * 
 * 此工厂类会：
 * 1. 自动从配置读取 CGB 支付配置
 * 2. 自动解析相对路径为绝对路径
 * 3. 自动注入日志记录器（如果可用）
 * 4. 创建并返回配置好的 CgbClient 实例
 */
class CgbClientFactory
{
    public function __invoke(ContainerInterface $container): CgbClient
    {
        // 获取配置接口
        $config = $container->get(ConfigInterface::class);
        
        // 读取 CGB 配置
        $cgbConfig = $config->get('cgb', []);
        
        // 处理相对路径，转换为绝对路径
        $cgbConfig = self::resolvePaths($cgbConfig);
        
        // 尝试获取日志记录器（可选）
        $logger = null;
        if ($container->has(LoggerInterface::class)) {
            try {
                $logger = $container->get(LoggerInterface::class);
            } catch (\Throwable $e) {
                // 日志记录器不可用时，使用 null
            }
        }
        
        // 创建并返回 CgbClient 实例
        return new CgbClient($cgbConfig, $logger);
    }
    
    /**
     * 解析配置文件中的相对路径为绝对路径
     * 
     * @param array $config 配置数组
     * @return array 处理后的配置数组
     */
    private static function resolvePaths(array $config): array
    {
        // 定义需要处理的路径字段
        $pathFields = ['private_key', 'public_key'];
        
        // 获取 BASE_PATH
        $basePath = self::getBasePath();
        
        foreach ($pathFields as $field) {
            if (isset($config[$field]) && !empty($config[$field])) {
                $path = $config[$field];
                
                // 如果不是绝对路径，且不是 PEM 字符串，则处理为相对路径
                if (!str_starts_with($path, '/') && 
                    !str_starts_with($path, '-----BEGIN') && 
                    !empty($path)) {
                    // 相对路径，基于 BASE_PATH
                    $absolutePath = rtrim($basePath, '/\\') . DIRECTORY_SEPARATOR . ltrim($path, '/\\');
                    
                    // 检查文件是否存在
                    if (file_exists($absolutePath)) {
                        $config[$field] = $absolutePath;
                    } else {
                        // 如果解析后的路径不存在，保留原值（可能是运行时生成的路径）
                        $config[$field] = $absolutePath;
                    }
                }
                // 如果是绝对路径或 PEM 字符串，保持不变
            }
        }
        
        return $config;
    }
    
    /**
     * 获取项目根目录路径
     * 
     * @return string 项目根目录路径
     */
    private static function getBasePath(): string
    {
        // 如果已定义 BASE_PATH，直接使用
        if (defined('BASE_PATH')) {
            return BASE_PATH;
        }
        
        // 尝试从环境变量获取
        $basePath = getenv('BASE_PATH');
        if ($basePath && is_dir($basePath)) {
            return $basePath;
        }
        
        // 尝试使用当前工作目录
        $basePath = getcwd();
        if ($basePath && is_dir($basePath)) {
            // 检查是否是 Hyperf 项目（有 bin/hyperf.php）
            if (file_exists($basePath . '/bin/hyperf.php')) {
                return $basePath;
            }
            // 检查是否有 composer.json
            if (file_exists($basePath . '/composer.json')) {
                return $basePath;
            }
        }
        
        // 最后尝试从包的父目录推断（向上查找包含 vendor 或 config 的目录）
        $currentDir = __DIR__;
        $parentDirs = [
            dirname($currentDir, 4), // packages/cgb-payment-sdk/src/Client -> project root
            dirname($currentDir, 5), // 再上一级
        ];
        
        foreach ($parentDirs as $dir) {
            if (is_dir($dir)) {
                if (file_exists($dir . '/composer.json') || file_exists($dir . '/config')) {
                    return $dir;
                }
            }
        }
        
        // 如果都失败，返回当前工作目录或包的父目录
        return $basePath ?: dirname(__DIR__, 3);
    }
}

