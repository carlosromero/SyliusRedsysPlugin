<?php

namespace Eclyptox\SyliusRedsysPlugin\Payum\Action;

use ArrayAccess;
use Eclyptox\SyliusRedsysPlugin\Payum\Api;
use Payum\Core\Action\ActionInterface;
use Payum\Core\ApiAwareInterface;
use Payum\Core\ApiAwareTrait;
use Payum\Core\Bridge\Spl\ArrayObject;
use Payum\Core\Exception\RequestNotSupportedException;
use Payum\Core\GatewayAwareInterface;
use Payum\Core\GatewayAwareTrait;
use Payum\Core\Reply\HttpPostRedirect;
use Payum\Core\Reply\HttpResponse;
use Payum\Core\Request\Capture;
use Payum\Core\Request\GetHttpRequest;
use Payum\Core\Security\GenericTokenFactoryAwareInterface;
use Payum\Core\Security\GenericTokenFactoryAwareTrait;

class CaptureAction implements ActionInterface, ApiAwareInterface, GenericTokenFactoryAwareInterface, GatewayAwareInterface
{    
    use GatewayAwareTrait;
    use ApiAwareTrait;
    use GenericTokenFactoryAwareTrait;

    public function __construct()
    {
        $this->apiClass = Api::class;
    }

    /**
     * {@inheritDoc}
     */
    public function execute($request)
    {
        /** @var $request Capture */
        RequestNotSupportedException::assertSupports($this, $request);

        $postData = ArrayObject::ensureArrayObject($request->getModel());

        //If the notification is late for some reason, the details are not update and it starts an infinite loop between
        //redsys and capture-url with error ds_order number repeated error.
        // So we check here if this is the capture-url called from redsys with payment info
        // to update details and redirect to afterpay-url
        $this->gateway->execute($httpRequest = new GetHttpRequest());

        if (array_key_exists('Ds_Signature', $httpRequest->query) && (null !== $httpRequest->query['Ds_Signature'])) {
            if (!array_key_exists('Ds_MerchantParameters', $httpRequest->query) || (null === $httpRequest->query['Ds_MerchantParameters'])) {
                throw new HttpResponse('The notification is invalid', 400);
            }

            if (false == $this->api->validateNotificationSignature($httpRequest->query)) {
                throw new HttpResponse('The notification is invalid', 400);
            }

            // After migrating to sha256, DS_Response param is not present in the
            // post request sent by the bank. Instead, bank sends an encoded string
            //  our gateway needs to decode.
            // Once this is decoded we need to add this info to the details among
            // with the $httpRequest->request part

            $postData->replace(
                ArrayObject::ensureArrayObject(
                    json_decode(base64_decode(strtr($httpRequest->query['Ds_MerchantParameters'], '-_', '+/')))
                )->toUnsafeArray() +
                $httpRequest->query
            );

          }
    
        if (empty($postData['Ds_Merchant_MerchantURL']) && $request->getToken() && $this->tokenFactory) {
            $notifyToken = $this->tokenFactory->createNotifyToken(
                $request->getToken()->getGatewayName(),
                $request->getToken()->getDetails()
            );

            $postData['Ds_Merchant_MerchantURL'] = $notifyToken->getTargetUrl();
        }

        $postData->validatedKeysSet(
            array(
                'Ds_Merchant_Amount',
                'Ds_Merchant_Order',
                'Ds_Merchant_Currency',
                'Ds_Merchant_TransactionType',
                'Ds_Merchant_MerchantURL',
            )
        );

        $details['Ds_Merchant_MerchantCode'] = $this->api->getMerchantCode();
        $details['Ds_Merchant_Terminal'] = $this->api->getMerchantTerminalCode();
        if ($this->api->getBizum()) {
            $postData['DS_MERCHANT_PAYMETHODS'] = 'z';
        }

        if (false == $postData['Ds_Merchant_UrlOK'] && $request->getToken()) {
            $postData['Ds_Merchant_UrlOK'] = $request->getToken()
                ->getTargetUrl();
        }
        if (false == $postData['Ds_Merchant_UrlKO'] && $request->getToken()) {
            $postData['Ds_Merchant_UrlKO'] = $request->getToken()
                ->getTargetUrl();
        }

        $details['Ds_SignatureVersion'] = Api::SIGNATURE_VERSION;

        if (false == $postData['Ds_MerchantParameters'] && $request->getToken()) {
            $details['Ds_MerchantParameters'] = $this->api->createMerchantParameters($postData->toUnsafeArray());
        }

        if (false == $postData['Ds_Signature']) {
            $details['Ds_Signature'] = $this->api->sign($postData->toUnsafeArray());

            throw new HttpPostRedirect($this->api->getRedsysUrl(), $details);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function supports($request)
    {
        return
            $request instanceof Capture &&
            $request->getModel() instanceof ArrayAccess;
    }
}
