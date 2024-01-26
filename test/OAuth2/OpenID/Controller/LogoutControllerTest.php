<?php

namespace OAuth2\OpenID\Controller;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response as Psr7Response;
use OAuth2\GrantType\AuthorizationCode;
use OAuth2\Log\TestLog;
use OAuth2\LogInterface;
use OAuth2\OpenID\RequestType\LogoutToken;
use OAuth2\Storage\Bootstrap;
use OAuth2\Server;
use OAuth2\Request;
use OAuth2\Request\TestRequest;
use OAuth2\Response;
use PHPUnit\Framework\TestCase;

class LogoutControllerTest extends TestCase
{
    protected $storage;

    public function testLogout()
    {
        $session_id = 'dfaadsffads1';
        $user_id = 'abcd123';

        $server = $this->getTestServer(['discovery_configuration' => ['backchannel_logout_supported' => true]]);

        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'client_id' => 'Test Client Backchannel Logout', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code' => 'testcode2',
        ));

        $server->handleTokenRequest($request, $response = new Response(), $session_id);

        $session = $this->storage->getSession($session_id);
        $sessionTokens = $this->storage->getSessionTokens($session_id);
        $loggedInRPs = $this->storage->getLoggedInRPs($session_id);

        $this->assertEquals($session['session_id'], $session_id);
        $this->assertEquals($session['user_id'], $user_id);
        $this->assertNotNull($session['sid']);

        $this->assertEquals(2, count($sessionTokens));
        $this->assertEquals($session_id, $sessionTokens[0]['session_id']);
        $this->assertEquals($session_id, $sessionTokens[1]['session_id']);

        $this->assertEquals(1, count($loggedInRPs));
        $this->assertEquals($session_id, $loggedInRPs[0]['session_id']);
        $this->assertEquals('Test Client Backchannel Logout', $loggedInRPs[0]['client_id']);

        // Try to logout
        $testLog = new TestLog();

        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(200),
        ]);
    
        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $server->handleLogoutSession($testLog, $client, $session_id, $user_id);

        //check if logout was successful
        $session = $this->storage->getSession($session_id);
        $sessionTokens = $this->storage->getSessionTokens($session_id);
        $loggedInRPs = $this->storage->getLoggedInRPs($session_id);
        $accessToken = $this->storage->getAccessToken('testcode2');

        $this->assertFalse($session);
        $this->assertFalse($accessToken);
        $this->assertEquals(0, count($sessionTokens));
        $this->assertEquals(0, count($loggedInRPs));
    }


    public function testLogoutNoBackchannelUri()
    {
        $session_id = 'dfaadsffads2';
        $user_id = 'abcd123';

        $token = 'testcode3';
        $sid = 'asdfadsfd';
        $expires = time() + 3600;

        $config = [
            'issuer' => 'phpunit',
        ];

        $this->getTestServer();

        $this->storage->setSession($session_id, $user_id, $sid, $expires);
        $this->storage->setSessionToken($session_id, $token);
        $this->storage->setLoggedInRPByToken($session_id, $token);

        // Try to logout
        $testLog = new TestLog();

        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(200),
        ]);
    
        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config));
        $logoutController->logoutSession($testLog, $client, $session_id, $user_id);

        $session = $this->storage->getSession($session_id);
        $sessionTokens = $this->storage->getSessionTokens($session_id);
        $loggedInRPs = $this->storage->getLoggedInRPs($session_id);
        $accessToken = $this->storage->getAccessToken($token);

        $this->assertFalse($session);
        $this->assertFalse($accessToken);
        $this->assertEquals(0, count($sessionTokens));
        $this->assertEquals(1, count($loggedInRPs));
    }

    public function testLogoutRequestFailed()
    {
        $session_id = 'dfaadsffads3';
        $token = 'afdadsf';
        $sid = 'asdfadsfd';
        $client_id = 'Test Client Backchannel Logout';
        $user_id = 'abcd123';
        $expires = time() + 3600;

        $config = [
            'issuer' => 'phpunit',
        ];

        $this->getTestServer();

        $this->storage->setSession($session_id, $user_id, $sid, $expires);
        $this->storage->setAccessToken($token, $client_id, $user_id, $expires);
        $this->storage->setSessionToken($session_id, $token);
        $this->storage->setLoggedInRPByToken($session_id, $token);

        // Try to logout
        $testLog = new TestLog();

        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(400),
        ]);

        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config));
        $logoutController->logoutSession($testLog, $client, $session_id, $user_id);

        $session = $this->storage->getSession($session_id);
        $sessionTokens = $this->storage->getSessionTokens($session_id);
        $loggedInRPs = $this->storage->getLoggedInRPs($session_id);
        $accessToken = $this->storage->getAccessToken($token);

        $this->assertFalse($session);
        $this->assertFalse($accessToken);
        $this->assertEquals(0, count($sessionTokens));
        $this->assertEquals(1, count($loggedInRPs));
        
    }

    public function testLogoutRefreshTokenNotRemovedWhenCorrectScope()
    {
        $session_id = 'dfaadsffads4';
        $access_token = 'afdadsf';
        $refresh_token = 'd3333';
        $sid = 'asdfadsfd';
        $client_id = 'Test Client Backchannel Logout';
        $user_id = 'abcd123';
        $expires = time() + 3600;

        $config = [
            'issuer' => 'phpunit',
        ];

        $this->getTestServer();

        $this->storage->setSession($session_id, $user_id, $sid, $expires);
        $this->storage->setAccessToken($access_token, $client_id, $user_id, $expires);
        $this->storage->setRefreshToken($refresh_token, $client_id, $user_id, $expires, 'offline_access');
        $this->storage->setSessionToken($session_id, $access_token);
        $this->storage->setSessionToken($session_id, $refresh_token, true);
        $this->storage->setLoggedInRPByToken($session_id, $access_token);

        // Try to logout
        $testLog = new TestLog();

        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(400),
        ]);

        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config));
        $logoutController->logoutSession($testLog, $client, $session_id, $user_id);

        $session = $this->storage->getSession($session_id);
        $sessionTokens = $this->storage->getSessionTokens($session_id);
        $loggedInRPs = $this->storage->getLoggedInRPs($session_id);
        $accessToken = $this->storage->getAccessToken($access_token);
        $refreshToken = $this->storage->getRefreshToken($refresh_token);

        $this->assertFalse($session);
        $this->assertFalse($accessToken);
        $this->assertNotFalse($refreshToken);
        $this->assertEquals(0, count($sessionTokens));
        $this->assertEquals(1, count($loggedInRPs));
    }

    public function testLogoutRefreshTokenGetsRemovedWhenNotCorrectScope()
    {
        $session_id = 'dfaadsffads5';
        $access_token = 'afdadsf';
        $refresh_token = 'd33334';
        $sid = 'asdfadsfd';
        $client_id = 'Test Client Backchannel Logout';
        $user_id = 'abcd123';
        $expires = time() + 3600;

        $config = [
            'issuer' => 'phpunit',
        ];

        $this->getTestServer();

        $this->storage->setSession($session_id, $user_id, $sid, $expires);
        $this->storage->setAccessToken($access_token, $client_id, $user_id, $expires);
        $this->storage->setRefreshToken($refresh_token, $client_id, $user_id, $expires);
        $this->storage->setSessionToken($session_id, $access_token);
        $this->storage->setSessionToken($session_id, $refresh_token, true);
        $this->storage->setLoggedInRPByToken($session_id, $access_token);

        // Try to logout
        $testLog = new TestLog();

        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(400),
        ]);

        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config));
        $logoutController->logoutSession($testLog, $client, $session_id, $user_id);

        $session = $this->storage->getSession($session_id);
        $sessionTokens = $this->storage->getSessionTokens($session_id);
        $loggedInRPs = $this->storage->getLoggedInRPs($session_id);
        $accessToken = $this->storage->getAccessToken($access_token);
        $refreshToken = $this->storage->getRefreshToken($refresh_token);

        $this->assertFalse($session);
        $this->assertFalse($accessToken);
        $this->assertFalse($refreshToken);
        $this->assertEquals(0, count($sessionTokens));
        $this->assertEquals(1, count($loggedInRPs));
    }

    private function getTestServer($config = array())
    {
        
        $config += array(
            'use_openid_connect' => true,
            'issuer'             => 'phpunit',
            'allow_implicit'     => true
        );
        
        $this->storage = Bootstrap::getInstance()->getSqlitePdo();
        $server = new Server($this->storage, $config);
        // Add the two types supported for authorization grant
        $server->addGrantType(new AuthorizationCode($this->storage));

        return $server;
    }
}