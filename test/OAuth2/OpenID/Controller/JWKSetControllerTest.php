<?php

namespace OAuth2\OpenID\Controller;

use OAuth2\Storage\Bootstrap;
use OAuth2\Storage\Memory;
use OAuth2\Request;
use OAuth2\Response;
use PHPUnit\Framework\TestCase;

class JWKSetControllerTest extends TestCase
{
    public function testHandleJWKSetRequestReturnsOk()
    {
        $controller = new JWKSetController($this->getPublicKeyStorage());

        $response = new Response();
        $controller->handleJWKSetRequest(new Request(), $response);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testHandleJWKSetRequestExposesPublicKey()
    {
        $controller = new JWKSetController($this->getPublicKeyStorage());

        $response = new Response();
        $controller->handleJWKSetRequest(new Request(), $response);

        $parameters = $response->getParameters();
        $this->assertArrayHasKey('keys', $parameters);
        $this->assertCount(1, $parameters['keys']);

        $key = $parameters['keys'][0];
        $this->assertInstanceOf(\Jose\Component\Core\JWK::class, $key);
        $this->assertEquals('RSA', $key->get('kty'));
        $this->assertTrue($key->has('n'));
        $this->assertTrue($key->has('e'));
    }

    public function testHandleJWKSetRequestNeverExposesPrivateKeyMaterial()
    {
        $controller = new JWKSetController($this->getPublicKeyStorage());

        $response = new Response();
        $controller->handleJWKSetRequest(new Request(), $response);

        $key = $response->getParameters()['keys'][0];
        // "d" is the RSA private exponent and must never leak through a JWK Set
        $this->assertFalse($key->has('d'));
    }

    public function testHandleJWKSetRequestSetsCacheHeaders()
    {
        $controller = new JWKSetController($this->getPublicKeyStorage());

        $response = new Response();
        $controller->handleJWKSetRequest(new Request(), $response);

        $this->assertEquals('no-store', $response->getHttpHeader('Cache-Control'));
        $this->assertEquals('no-cache', $response->getHttpHeader('Pragma'));
        $this->assertEquals('application/json', $response->getHttpHeader('Content-Type'));
    }

    public function testValidateJWKSetRequestAlwaysSucceeds()
    {
        $controller = new JWKSetController($this->getPublicKeyStorage());

        $this->assertTrue($controller->validateJWKSetRequest(new Request(), new Response()));
    }

    private function getPublicKeyStorage(): Memory
    {
        return Bootstrap::getInstance()->getMemoryStorage();
    }
}
