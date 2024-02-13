<?php

namespace OAuth2\OpenID\Controller;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response as Psr7Response;
use OAuth2\GrantType\AuthorizationCode;
use OAuth2\GrantType\RefreshToken;
use OAuth2\Log\TestLog;
use OAuth2\OpenID\RequestType\LogoutToken;
use OAuth2\OpenID\ResponseType\IdToken;
use OAuth2\Storage\Bootstrap;
use OAuth2\Server;
use OAuth2\Request\TestRequest;
use OAuth2\Response;
use PHPUnit\Framework\TestCase;

class LogoutControllerTest extends TestCase
{
    protected $storage;

    protected $grantTypes;

    public function testLogout()
    {
        $session_id = 'dfaadsffads1';
        $user_id = 'abcd123';
        $client_id = 'Test Client Backchannel Logout';

        $server = $this->getTestServer(['discovery_configuration' => ['backchannel_logout_supported' => true]]);

        $sid = 'asdfadsfd';
        $expires = time() + 3600;
        $this->storage->setSession($session_id, $user_id, $sid, $expires);
        $this->storage->setAuthorizationCode('testcode2', $client_id, $user_id, '', $expires, null, null, null, null, $sid);

        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'client_id' => $client_id, // valid client id
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
        $this->assertEquals($client_id, $loggedInRPs[0]['client_id']);

        // Try to logout
        $testLog = new TestLog();
    
        $server->handleLogoutRP($testLog, $client_id, $session_id);

        //check if logout was successful
        $session = $this->storage->getSession($session_id);
        $sessionTokens = $this->storage->getSessionTokens($session_id);
        $loggedInRPs = $this->storage->getLoggedInRPs($session_id);
        $accessToken = $this->storage->getAccessToken('testcode2');

        $this->assertNotFalse($session);
        $this->assertFalse($accessToken);
        $this->assertEquals(0, count($sessionTokens));
        $this->assertEquals(0, count($loggedInRPs));
    }


    public function testLogoutNoBackchannelUri()
    {
        $session_id = 'dfaadsffads2';
        $user_id = 'abcd123';
        $client_id = 'Test Client Backchannel Logout No Uri';

        $token = 'testcode3';
        $sid = 'asdfadsfd';
        $expires = time() + 3600;

        $config = [
            'issuer' => 'phpunit',
        ];

        $server = $this->getTestServer();

        $this->storage->setSession($session_id, $user_id, $sid, $expires);
        $this->storage->setSessionToken($session_id, $token, $client_id);
        $this->storage->setLoggedInRPByToken($session_id, $token);

        // Try to logout
        $testLog = new TestLog();

        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(200),
        ]);
    
        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $idTokenResponse = new IdToken($this->storage, $this->storage, $config);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config), $idTokenResponse, $this->grantTypes, $config, $client);
        $logoutController->handleLogoutRP($testLog, $client_id, $session_id);

        $session = $this->storage->getSession($session_id);
        $sessionTokens = $this->storage->getSessionTokens($session_id);
        $loggedInRPs = $this->storage->getLoggedInRPs($session_id);
        $accessToken = $this->storage->getAccessToken($token);

        $this->assertNotFalse($session);
        $this->assertFalse($accessToken);
        $this->assertEquals(0, count($sessionTokens));
        $this->assertEquals(0, count($loggedInRPs));
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
        $this->storage->setSessionToken($session_id, $token, $client_id);
        $this->storage->setLoggedInRPByToken($session_id, $token);

        // Try to logout
        $testLog = new TestLog();

        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(200),
        ]);
    
        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $idTokenResponse = new IdToken($this->storage, $this->storage, $config);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config), $idTokenResponse, $this->grantTypes, $config, $client);
        $logoutController->handleLogoutRP($testLog, $client_id, $session_id);

        $session = $this->storage->getSession($session_id);
        $sessionTokens = $this->storage->getSessionTokens($session_id);
        $loggedInRPs = $this->storage->getLoggedInRPs($session_id);
        $accessToken = $this->storage->getAccessToken($token);

        $this->assertNotFalse($session);
        $this->assertFalse($accessToken);
        $this->assertEquals(0, count($sessionTokens));
        $this->assertEquals(0, count($loggedInRPs));
        
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
        $this->storage->setSessionToken($session_id, $access_token, $client_id);
        $this->storage->setSessionToken($session_id, $refresh_token, $client_id, true);
        $this->storage->setLoggedInRPByToken($session_id, $access_token);

        // Try to logout
        $testLog = new TestLog();

        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(200),
        ]);
    
        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $idTokenResponse = new IdToken($this->storage, $this->storage, $config);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config), $idTokenResponse, $this->grantTypes, $config, $client);
        $logoutController->handleLogoutRP($testLog, $client_id, $session_id);

        $session = $this->storage->getSession($session_id);
        $sessionTokens = $this->storage->getSessionTokens($session_id);
        $loggedInRPs = $this->storage->getLoggedInRPs($session_id);
        $accessToken = $this->storage->getAccessToken($access_token);
        $refreshToken = $this->storage->getRefreshToken($refresh_token);

        $this->assertNotFalse($session);
        $this->assertFalse($accessToken);
        $this->assertNotFalse($refreshToken);
        $this->assertEquals(0, count($sessionTokens));
        $this->assertEquals(0, count($loggedInRPs));
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
        $this->storage->setSessionToken($session_id, $access_token, $client_id);
        $this->storage->setSessionToken($session_id, $refresh_token, $client_id, true);
        $this->storage->setLoggedInRPByToken($session_id, $access_token);

        // Try to logout
        $testLog = new TestLog();

        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(200),
        ]);
    
        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $idTokenResponse = new IdToken($this->storage, $this->storage, $config);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config), $idTokenResponse, $this->grantTypes, $config, $client);
        $logoutController->handleLogoutRP($testLog, $client_id, $session_id);

        $session = $this->storage->getSession($session_id);
        $sessionTokens = $this->storage->getSessionTokens($session_id);
        $loggedInRPs = $this->storage->getLoggedInRPs($session_id);
        $accessToken = $this->storage->getAccessToken($access_token);
        $refreshToken = $this->storage->getRefreshToken($refresh_token);

        $this->assertNotFalse($session);
        $this->assertFalse($accessToken);
        $this->assertFalse($refreshToken);
        $this->assertEquals(0, count($sessionTokens));
        $this->assertEquals(0, count($loggedInRPs));
    }

    public function testHandleLogoutSession()
    {
        $session_id = 'dfaadsffads2';
        $user_id = 'abcd123';
        $clientId = 'Test Client Backchannel Logout';

        $token = 'testcode4';
        $sid = 'asdfadsfd';
        $expires = time() + 3600;


        $config = [
            'issuer' => 'phpunit',
        ];

        $server = $this->getTestServer();

        $this->storage->setSession($session_id, $user_id, $sid, $expires);
        $this->storage->setSessionToken($session_id, $token, $clientId);
        $this->storage->setLoggedInRPByToken($session_id, $token);

        // Try to logout
        $testLog = new TestLog();

        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(200),
        ]);
    
        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $idTokenResponse = new IdToken($this->storage, $this->storage, $config);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config), $idTokenResponse, $this->grantTypes, $config, $client);
        $logoutController->handleLogoutSession($testLog, $session_id, $user_id);

        $session = $this->storage->getSession($session_id);
        $sessionTokens = $this->storage->getSessionTokens($session_id);
        $loggedInRPs = $this->storage->getLoggedInRPs($session_id);
        $accessToken = $this->storage->getAccessToken($token);

        $this->assertFalse($session);
        $this->assertFalse($accessToken);
        $this->assertEquals(0, count($sessionTokens));
        $this->assertEquals(0, count($loggedInRPs));
    }

    public function testHandleLogoutRP()
    {
        $session_id = 'dfaadsffads2';
        $user_id = 'abcd123';
        $client_id = 'Test Client Backchannel Logout';

        $token = 'testcode4';
        $sid = 'asdfadsfd';
        $expires = time() + 3600;


        $config = [
            'issuer' => 'phpunit',
        ];

        $server = $this->getTestServer();

        $this->storage->setSession($session_id, $user_id, $sid, $expires);
        $this->storage->setSessionToken($session_id, $token, $client_id);
        $this->storage->setLoggedInRPByToken($session_id, $token);
        $accessToken = $this->storage->setAccessToken($token, $client_id, $user_id, time());

        // Try to logout
        $testLog = new TestLog();

        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(200),
        ]);
    
        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $idTokenResponse = new IdToken($this->storage, $this->storage, $config);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config), $idTokenResponse, $this->grantTypes, $config, $client);
        $logoutController->handleLogoutRP($testLog, $client_id, $session_id);

        $session = $this->storage->getSession($session_id);
        $sessionTokens = $this->storage->getSessionTokens($session_id);
        $loggedInRPs = $this->storage->getLoggedInRPs($session_id);
        $accessToken = $this->storage->getAccessToken($token);

        $this->assertNotFalse($session);
        $this->assertFalse($accessToken);
        $this->assertEquals(0, count($sessionTokens));
        $this->assertEquals(0, count($loggedInRPs));
    }

    public function testSetHandleTokenSession()
    {
        
        $config = [
            'issuer'             => 'phpunit',
            'session_lifetime'   => 3600,
        ];

        $token = 'testcode4';
        $userId = 'abcd123';
        $clientId = 'Test Client Backchannel Logout';
        $sessionId = 'session123456';

        $request = TestRequest::createPost(array(
            'client_id'     => $clientId, // valid client id
            'redirect_uri'  => 'http://adobe.com', // valid redirect URI
            'state'         => 'af0ifjsldkj',
            'grant_type'    => 'authorization_code',
            'code'          => $token,
            'client_secret' => 'TestSecret', // valid client secret
        ));

        $response = new Response();

        $server = $this->getTestServer();

        $accessToken = $this->storage->setAccessToken($token, $clientId, $userId, time());
        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(200),
        ]);
    
        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $idTokenResponse = new IdToken($this->storage, $this->storage, $config);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config), $idTokenResponse, $this->grantTypes, $config, $client);

        $token = ['access_token' => 'testcode4', 'refresh_token' => 'testcode4'];

        $this->grantTypes['authorization_code']->validateRequest($request, $response);
        $logoutController->setHandleTokenSession($request, $token);

        $sessionTokens = $this->storage->getSessionTokens($sessionId);
        $loggedInRPs = $this->storage->getLoggedInRPs($sessionId);

        $this->assertEquals('testcode4', $sessionTokens[0]['token']);
        $this->assertEquals($sessionId, $sessionTokens[0]['session_id']);
        $this->assertEquals($sessionId, $loggedInRPs[0]['session_id']);
        $this->assertEquals($clientId, $loggedInRPs[0]['client_id']);
    }

    public function testValidateRPLogoutRequest()
    {
        $this->getTestServer();

        $config = [
            'issuer'             => 'phpunit',
            'session_lifetime'   => 3600,
        ];

        $idTokenResponse = new IdToken($this->storage, $this->storage, $config);

        $clientId = 'test_client';
        $idToken = $idTokenResponse->createIdToken($clientId, '');

        $request = TestRequest::createPost(array(
            'id_token_hint' => $idToken,
            'client_id' => 'test_client',
        ));

        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(200),
        ]);
    
        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config), $idTokenResponse, $this->grantTypes, $config, $client);

        $validationResult = $logoutController->validateRPLogoutRequest($request, $response = new Response());

        $this->assertTrue($validationResult);
    }

    public function testValidateRPLogoutRequestClientNotMatch()
    {
        $this->getTestServer();

        $config = [
            'issuer'             => 'phpunit',
            'session_lifetime'   => 3600,
        ];

        $idTokenResponse = new IdToken($this->storage, $this->storage, $config);

        $clientId = 'test_client';
        $idToken = $idTokenResponse->createIdToken($clientId, '');

        $request = TestRequest::createPost(array(
            'id_token_hint' => $idToken,
            'client_id' => 'test_client2',
        ));

        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(200),
        ]);
    
        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config), $idTokenResponse, $this->grantTypes, $config, $client);

        $validationResult = $logoutController->validateRPLogoutRequest($request, $response = new Response());

        $this->assertFalse($validationResult);
    }

    public function testValidateRPLogoutRequestLogoutRedirectUriInClient()
    {
        $this->getTestServer();

        $config = [
            'issuer'             => 'phpunit',
            'session_lifetime'   => 3600,
        ];

        $idTokenResponse = new IdToken($this->storage, $this->storage, $config);

        $clientId = 'Test Client Backchannel Logout';
        $idToken = $idTokenResponse->createIdToken($clientId, '');

        $request = TestRequest::createPost(array(
            'id_token_hint' => $idToken,
            'logout_redirect_uri' => 'https://example.org'
        ));

        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(200),
        ]);
    
        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config), $idTokenResponse, $this->grantTypes, $config, $client);

        $validationResult = $logoutController->validateRPLogoutRequest($request, $response = new Response());

        $this->assertTrue($validationResult);
    }

    public function testValidateRPLogoutRequestLogoutRedirectUriNotInClient()
    {
        $this->getTestServer();

        $config = [
            'issuer'             => 'phpunit',
            'session_lifetime'   => 3600,
        ];

        $idTokenResponse = new IdToken($this->storage, $this->storage, $config);

        $clientId = 'Test Client Backchannel Logout';
        $idToken = $idTokenResponse->createIdToken($clientId, '');

        $request = TestRequest::createPost(array(
            'id_token_hint' => $idToken,
            'logout_redirect_uri' => 'test'
        ));

        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(200),
        ]);
    
        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config), $idTokenResponse, $this->grantTypes, $config, $client);

        $validationResult = $logoutController->validateRPLogoutRequest($request, $response = new Response());

        $this->assertFalse($validationResult);
    }

    public function testSetSession()
    {
        $this->getTestServer();

        $config = [
            'issuer'             => 'phpunit',
            'session_lifetime'   => 3600,
        ];

        $idTokenResponse = new IdToken($this->storage, $this->storage, $config);
        
        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(200),
        ]);
    
        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config), $idTokenResponse, $this->grantTypes, $config, $client);

        $sessionResult = $logoutController->setSession('test123', 'user456');

        $this->assertNotNull($sessionResult);
        $this->assertEquals('test123', $sessionResult['session_id']);
        $this->assertEquals('user456', $sessionResult['user_id']);
        $this->assertNotNull($sessionResult['sid']);
        $this->assertNotNull($sessionResult['expires']);
    }

    public function testSetSessionUpdateExpires()
    {
        $this->getTestServer();

        $sessionId = '2session123456';
        $userId = 'abcd123';
        $config = [
            'issuer'             => 'phpunit',
            'session_lifetime'   => 3600,
        ];

        $idTokenResponse = new IdToken($this->storage, $this->storage, $config);
        
        //mock guzzle for backchanel logout uri
        $mock = new MockHandler([
            new Psr7Response(200),
        ]);
    
        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $logoutController = new LogoutController($this->storage, $this->storage, $this->storage, $this->storage, new LogoutToken($this->storage, $this->storage, $config), $idTokenResponse, $this->grantTypes, $config, $client);

        $initalSession = $this->storage->getSession($sessionId);
        $sessionResult = $logoutController->setSession($sessionId, $userId);

        $this->assertNotEquals($initalSession['expires'], $sessionResult['expires']);
        $this->assertEquals($sessionId, $sessionResult['session_id']);
        $this->assertEquals($userId, $sessionResult['user_id']);
        $this->assertNotNull($sessionResult['sid']);
        $this->assertNotNull($sessionResult['expires']);
    }

    private function getTestServer($config = array())
    {
        
        $config += array(
            'use_openid_connect' => true,
            'issuer'             => 'phpunit',
            'allow_implicit'     => true,
            'session_lifetime'   => 3600
        );
        
        $this->storage = Bootstrap::getInstance()->getSqlitePdo();
        $server = new Server($this->storage, $config);
        // Add the two types supported for authorization grant
        $server->addGrantType(new AuthorizationCode($this->storage));

        $this->grantTypes['authorization_code'] = new AuthorizationCode($this->storage);
        $this->grantTypes['refresh_token'] = new RefreshToken($this->storage);

        return $server;
    }


}