<?php
namespace OAuth2\OpenID\Controller;

use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\Storage\PublicKeyInterface;
use Strobotti\JWK\KeyFactory;
use Strobotti\JWK\KeySet;

class JWKSetController implements JWKSetControllerInterface
{
    protected $publicKeyStorage;

    public function __construct(PublicKeyInterface $publicKeyStorage)
    {
        $this->publicKeyStorage = $publicKeyStorage;
    }

    public function handleJWKSetRequest(RequestInterface $request, ResponseInterface $response)
    {
        $options = [
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => 'eXaunmL',
         ];
         
        $keyFactory = new KeyFactory();
        $key = $keyFactory->createFromPem($this->publicKeyStorage->getPublicKey(), $options);

        $keySet = new KeySet();
        $keySet->addKey($key);
        $keys = $keySet->jsonSerialize();

        $response->setStatusCode(200);
        $response->addParameters([
            $keys
        ]);
        $response->addHttpHeaders(array(
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
            'Content-Type' => 'application/json'
        ));
    }

    public function validateJWKSetRequest(RequestInterface $request, ResponseInterface $response)
    {
        // Nothing to validate here
        return true;
    }
}
