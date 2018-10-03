<?php
namespace OAuth2\OpenID\Controller;

use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\Storage\PublicKeyInterface;
use JOSE_JWK;
use phpseclib\Crypt\RSA;

class JWKSetController implements JWKSetControllerInterface
{
    protected $publicKeyStorage;

    public function __construct(PublicKeyInterface $publicKeyStorage)
    {
        $this->publicKeyStorage = $publicKeyStorage;
    }

    public function handleJWKSetRequest(RequestInterface $request, ResponseInterface $response)
    {
        $rsa = new RSA();
        $rsa->loadKey($this->publicKeyStorage->getPublicKey());

        $jwk = JOSE_JWK::encode($rsa);
        $jwks = [
            $jwk->components
        ];

        $response->setStatusCode(200);
        $response->addParameters([
            'keys' => $jwks
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
