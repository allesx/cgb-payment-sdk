<?php

declare(strict_types=1);

/**
 * Hyperf 框架使用示例
 * 演示如何在 Hyperf 框架中集成和使用 CGB 支付 SDK
 */

namespace App\Controller\Payment;

use Allesx\CgbPayment\Client\CgbClient;
use Hyperf\HttpServer\Annotation\Controller;
use Hyperf\HttpServer\Annotation\PostMapping;
use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\HttpServer\Contract\ResponseInterface;

#[Controller(prefix: '/cgb')]
class CgbController
{
    /**
     * 方式 1：通过构造函数注入（推荐）
     * SDK 会自动从 config/autoload/cgb.php 读取配置
     */
    public function __construct(
        private CgbClient $cgbClient
    ) {
    }
    
    /**
     * 账户查询接口（0001）
     * 对应 Java SDK 的 E1010001Test
     */
    #[PostMapping('/account/query')]
    public function accountQuery(RequestInterface $request): array
    {
        $body = [
            'account' => $request->input('account', ''),
            'ccyType' => $request->input('ccyType', '156'), // 156=人民币
        ];
        
        $result = $this->cgbClient->request('0001', $body);
        
        if (!empty($result['parsed'])) {
            return [
                'code' => 200,
                'message' => 'success',
                'data' => $result['parsed']['Body'] ?? [],
            ];
        }
        
        return [
            'code' => 500,
            'message' => $result['decrypt_error'] ?? '请求失败',
            'data' => null,
        ];
    }
    
    /**
     * 付款接口（0021）
     * 对应 Java SDK 的 SimpleTrade 示例
     */
    #[PostMapping('/pay')]
    public function pay(RequestInterface $request): array
    {
        $body = [
            'tradeTypeNo' => $request->input('tradeTypeNo'),
            'entBizDt' => $request->input('entBizDt', date('Ymd')),
            'entBizId' => $request->input('entBizId'),
            'payerAcctNo' => $request->input('payerAcctNo'),
            'payerAcctName' => $request->input('payerAcctName'),
            'payeeAcctNo' => $request->input('payeeAcctNo'),
            'payeeAcctName' => $request->input('payeeAcctName'),
            'payeeBkFlag' => $request->input('payeeBkFlag', 'T'),
            'payeeBkNo' => $request->input('payeeBkNo'),
            'payeeBkName' => $request->input('payeeBkName'),
            'amount' => $request->input('amount'),
            'remark' => $request->input('remark', ''),
            'postscript' => $request->input('postscript', ''),
        ];
        
        $result = $this->cgbClient->request('0021', $body);
        
        if (!empty($result['parsed'])) {
            $header = $result['parsed']['Header'] ?? [];
            return [
                'code' => $header['retCode'] === '000000' ? 200 : 500,
                'message' => $header['retMsg'] ?? 'success',
                'data' => $result['parsed']['Body'] ?? [],
                'retSeqNo' => $header['retSeqNo'] ?? '',
            ];
        }
        
        return [
            'code' => 500,
            'message' => $result['decrypt_error'] ?? '请求失败',
            'data' => null,
        ];
    }
    
    /**
     * 银行回调处理
     * 对应 Java SDK 的 CgbToErpTest
     */
    #[PostMapping('/notify')]
    public function notify(
        RequestInterface $request,
        ResponseInterface $response
    ): \Psr\Http\Message\ResponseInterface {
        // 从 HTTP 请求头获取
        $encryptKey = $request->header('encryptKey', '');
        $signature = $request->header('signature', '');
        $encryptedBody = $request->getBody()->getContents();
        
        if (empty($encryptKey) || empty($signature) || empty($encryptedBody)) {
            return $response->json([
                'code' => 400,
                'message' => '缺少必要参数',
            ]);
        }
        
        // 解密和验签
        $result = $this->cgbClient->processResponseDecryption($encryptKey, $signature, $encryptedBody);
        
        if (empty($result['parsed'])) {
            return $response->json([
                'code' => 500,
                'message' => $result['decryptError'] ?? '解密失败',
            ]);
        }
        
        // 处理业务逻辑（示例：记录通知）
        $notifyData = $result['parsed'];
        // TODO: 处理业务逻辑，如保存通知记录、更新订单状态等
        
        // 生成响应给银行
        $responseJson = json_encode([
            'Body' => [
                'bizRetInfo' => '动账通知成功',
                'bizRetCode' => '000000',
            ],
            'Header' => [
                'retSeqNo' => 'DEI' . time() . rand(1000, 9999),
                'tranTime' => date('His'),
                'seqNo' => $notifyData['Header']['seqNo'] ?? '',
                'entCstNo' => $this->cgbClient->getConfig()['ent_cst_no'] ?? '',
                'appId' => $this->cgbClient->getConfig()['app_id'] ?? '',
                'sysRetInfo' => '通讯成功',
                'tradeCode' => $notifyData['Header']['tradeCode'] ?? '',
                'sysRetCode' => '000000',
                'tranDate' => date('Ymd'),
                'resdFlag' => 'N',
            ],
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        
        // 签名响应
        $responseSignature = $this->cgbClient->generateSignature($responseJson);
        
        // 加密响应
        $sm4Key = $this->cgbClient->generateSecretKey();
        $encryptedResponse = $this->cgbClient->encryptContentWithSecretKey($responseJson, $sm4Key);
        $responseEncryptKey = $this->cgbClient->encryptSecretKey($sm4Key);
        
        // 返回给银行
        return $response
            ->withHeader('signature', $responseSignature)
            ->withHeader('appId', $this->cgbClient->getConfig()['app_id'])
            ->withHeader('encryptKey', $responseEncryptKey)
            ->withHeader('Content-Type', 'text/plain; charset=UTF-8')
            ->withBody(new \Hyperf\HttpMessage\Stream\SwooleStream($encryptedResponse));
    }
}

/**
 * 方式 2：从容器获取（适用于非控制器场景）
 */
class CgbService
{
    public function queryAccount(string $account): array
    {
        // 通过容器获取 CgbClient 实例
        $cgbClient = \Hyperf\Context\ApplicationContext::getContainer()
            ->get(\Allesx\CgbPayment\Client\CgbClient::class);
        
        return $cgbClient->request('0001', [
            'account' => $account,
            'ccyType' => '156',
        ]);
    }
}

/**
 * 方式 3：手动创建（不推荐，仅用于特殊场景）
 */
function manualExample(): void
{
    // 从配置读取
    $config = \Hyperf\Support\make(\Hyperf\Contract\ConfigInterface::class)
        ->get('cgb', []);
    
    $cgbClient = new \Allesx\CgbPayment\Client\CgbClient($config);
    
    $result = $cgbClient->request('0001', [
        'account' => '9550880401293700128',
        'ccyType' => '156',
    ]);
}

