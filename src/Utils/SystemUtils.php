<?php

declare(strict_types=1);

namespace Allesx\CgbPayment\Utils;

use Exception;

class SystemUtils
{
    public static function getMacAddress(?string $macAddress = null): string
    {
        if (!empty($macAddress)) {
            return $macAddress;
        }
        $macFromEnv = getenv('CGB_MAC_ADDRESS') ?: '';
        if (!empty($macFromEnv)) {
            return $macFromEnv;
        }
        try {
            $os = strtolower(PHP_OS);
            if (strpos($os, 'linux') !== false) {
                return self::getMacAddressLinux();
            }
            if (strpos($os, 'darwin') !== false || strpos($os, 'mac') !== false) {
                return self::getMacAddressMacOS();
            }
            if (strpos($os, 'win') !== false) {
                return self::getMacAddressWindows();
            }
            return self::getMacAddressGeneric();
        } catch (Exception $e) {
            return 'C8-58-C0-2D-32-E6';
        }
    }

    private static function getMacAddressLinux(): string
    {
        $interfaces = glob('/sys/class/net/*/address');
        if (!empty($interfaces)) {
            foreach ($interfaces as $interface) {
                if (strpos($interface, '/lo/') !== false) {
                    continue;
                }
                $mac = trim(@file_get_contents($interface));
                if (!empty($mac) && self::isValidMac($mac)) {
                    return strtoupper(str_replace(':', '-', $mac));
                }
            }
        }
        $output = @shell_exec('ip link show 2>/dev/null');
        if ($output && preg_match('/link\/ether\s+([0-9a-f:]+)/i', $output, $m)) {
            $mac = trim($m[1]);
            if (self::isValidMac($mac)) {
                return strtoupper(str_replace(':', '-', $mac));
            }
        }
        $output = @shell_exec('ifconfig 2>/dev/null');
        if ($output && preg_match('/ether\s+([0-9a-f:]+)/i', $output, $m)) {
            $mac = trim($m[1]);
            if (self::isValidMac($mac)) {
                return strtoupper(str_replace(':', '-', $mac));
            }
        }
        throw new Exception('无法获取MAC地址');
    }

    private static function getMacAddressMacOS(): string
    {
        $output = @shell_exec('networksetup -listallhardwareports 2>/dev/null');
        if ($output) {
            $lines = explode("\n", $output);
            $currentInterface = '';
            foreach ($lines as $line) {
                if (preg_match('/Hardware Port:\s*(.+)/', $line, $m)) {
                    $currentInterface = trim($m[1]);
                } elseif (preg_match('/Device:\s*(.+)/', $line, $m) && !empty($currentInterface)) {
                    $device = trim($m[1]);
                    if ($device !== 'none' && strpos($currentInterface, 'Bluetooth') === false) {
                        $mac = @shell_exec("ifconfig {$device} 2>/dev/null | grep ether | awk '{print \$2}'");
                        if ($mac) {
                            $mac = trim($mac);
                            if (self::isValidMac($mac)) {
                                return strtoupper(str_replace(':', '-', $mac));
                            }
                        }
                    }
                }
            }
        }
        $output = @shell_exec('ifconfig 2>/dev/null');
        if ($output) {
            $interfaces = ['en0', 'en1', 'eth0'];
            foreach ($interfaces as $interface) {
                if (preg_match("/{$interface}.*?ether\s+([0-9a-f:]+)/is", $output, $m)) {
                    $mac = trim($m[1]);
                    if (self::isValidMac($mac)) {
                        return strtoupper(str_replace(':', '-', $mac));
                    }
                }
            }
        }
        throw new Exception('无法获取MAC地址');
    }

    private static function getMacAddressWindows(): string
    {
        $output = @shell_exec('getmac /fo csv /nh 2>nul');
        if ($output) {
            foreach (explode("\n", $output) as $line) {
                $line = trim($line);
                if (empty($line)) {
                    continue;
                }
                if (preg_match('/"([^"]+)","([0-9A-F-]+)"/', $line, $m)) {
                    $mac = $m[2];
                    if (self::isValidMac($mac)) {
                        return strtoupper($mac);
                    }
                }
            }
        }
        $output = @shell_exec('ipconfig /all 2>nul');
        if ($output && preg_match('/Physical Address[\.\s]+:\s+([0-9A-F-]+)/i', $output, $m)) {
            $mac = trim($m[1]);
            if (self::isValidMac($mac)) {
                return strtoupper($mac);
            }
        }
        throw new Exception('无法获取MAC地址');
    }

    private static function getMacAddressGeneric(): string
    {
        $output = @shell_exec('ifconfig 2>/dev/null || ipconfig 2>/dev/null');
        if ($output && preg_match('/([0-9a-f]{2}[:-]){5}([0-9a-f]{2})/i', $output, $m)) {
            $mac = $m[0];
            if (self::isValidMac($mac)) {
                return strtoupper(str_replace(':', '-', $mac));
            }
        }
        throw new Exception('无法获取MAC地址');
    }

    private static function isValidMac(string $mac): bool
    {
        $mac = str_replace([':', '-'], '', $mac);
        return preg_match('/^[0-9A-Fa-f]{12}$/', $mac) === 1;
    }
}


