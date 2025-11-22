<?php

declare(strict_types=1);

// Prefer project root Composer autoloader if present
$rootAutoload = __DIR__ . '/../../vendor/autoload.php';
if (file_exists($rootAutoload)) {
    require $rootAutoload;
}

// Lightweight PSR-4 fallback for this package during development (path repository)
spl_autoload_register(function ($class) {
    $prefix = 'Allesx\\CgbPayment\\';
    $baseDir = __DIR__ . '/src/';
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }
    $relativeClass = substr($class, $len);
    $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';
    if (file_exists($file)) {
        require $file;
    }
});


