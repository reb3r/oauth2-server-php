<?php
namespace OAuth2\OpenID\Controller;

use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\Storage\PublicKeyInterface;

class JWKSetController implements JWKSetControllerInterface
{
    protected $publicKeyStorage;

    public function __construct(PublicKeyInterface $publicKeyStorage)
    {
        $this->publicKeyStorage = $publicKeyStorage;
    }

    public function handleJWKSetRequest(RequestInterface $request, ResponseInterface $response)
    {
        $key = JWKFactory::createFromKey($this->publicKeyStorage->getPublicKey());
        $keys = new JWKSet([$key]);

        $response->setStatusCode(200);
        $response->addParameters([
            'keys' => $keys->all()
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
