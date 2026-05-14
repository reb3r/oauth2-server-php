<?php

namespace OAuth2\GrantType;

use OAuth2\Storage\Bootstrap;
use OAuth2\Server;
use OAuth2\Request\TestRequest;
use OAuth2\Response;
use OAuth2\Encryption\Jwt;
use PHPUnit\Framework\TestCase;

class JwtBearerTest extends TestCase
{
    private $privateKey;

    public function setUp(): void
    {
        $this->privateKey = <<<EOD
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsbZDRKQG5K2TutHgH6KVsj7BovTwMRRPxXzFR0ZOghYhYceQ
QF5z+aoAscKOiS59UB1hpVb++tUofmrhZI7DULi/B+ngyWBGR627Mfr2PGFXo5Er
+JdsGj5aIjlMXW9yUgOY952HcbvC7wscuhHZaitZYTYMcXq8IJi0mmpZv3i8hKO0
RPdoMDqYfcNntnLSkwojEhERdqZq2l0mPqOIFY0FK8BrnUIkiu/rlGYk8NAywu+A
oorf0qk/tq316wjWQ+UN7nuO7M2JU2CEsLfTxG4E1T6dEWtqIW33Ho530M5xwXu8
omQoel0zMorrpUNLBflMUBFbVtls0ZTXDs4uwQIDAQABAoIBACHfp/rReS7llx8p
GhttljMfmzFAlvgD8yClo8TuNdC9/ybwLyLV3i1cpj075IdpgSFgOFiXuIp/TvSp
0sSkIb6lOGR9xAcefsby6pegSoc/1sCqz0LXOhfWgr+7RD8bGyNe5C1urX6UV5fQ
+mzNMi/2i1boQn7u8iUUdnhohSrlu0nVj7uyTku00IAOhS2mCXUa2/dyeFu42Vr/
yYynLRRjB6A0XDvHFOvYbfKmGnE2AQp+IW8i+fPs5RV1w2yxMwWzbkeamsF3mojI
CMmsz+gLZ3lxRYHzSEN8/qsFr/zCrzmpa4l3D4y1XvqP4UAPCjBYxihMJWEJQsFB
u3DIpvECgYEA3ac00XTwBZhkLG1TU9G0H8o0sKsODV+i6xrhU3cmpdu/HiysRWuG
IIprTYN9XrrfpSQ7I82R9gi2avJWAgneQqGGw5V5YZnZlm58bQMAvkUM/EVxrYdf
xIQsbUpTSSH2TkoJ73AL4tP45kzcqkRwb4vdyHgOOEPctOs/TK23RPsCgYEAzT/y
VnMxuVxYBC/vcAbxiiTM5lid3a6OVpnVvGRJSZoepRsyD2cxy7V8TS2ZPRW3IFco
2NSN1bplvF91hs5Mw9tJ9i6HVX0zzimc/X6MWAqqFK0hooBGSzlOSCsyWYEhgRJw
9Q7hJTGP6ogXbg3xjQq6aIZnBu7yeeCBDbrD9nMCgYEA0hRfUEKYF4WHNEBuINx5
70N0SxnlGLHTNSfl9njQ7ZRoAM5wfN9bYc4vw2jj03wk6l17nASD2gAJ/TUwZYA6
40Y693bdc68g9p5DWgLlmnDRzOx4wPK0xwpLHU67v23sB+nOntzAtz0XBBhHcS2q
r16OVynKuHNBZUwuU5u2Py8CgYAemdkcsIIKW803mpn9PtvGN+Rgt3eZ9It+N+NY
+i6/DX5iKWLWTxFqiL1mmFTPeaxa4wPRCCe5ZNgENMtF9P4W+VvWm2tMAKW3qBai
6Lot6jEfcgyguLVCQ+H6+o3AMHN5VfGHZ9eDfxcw5Wdw3h1UZPQT323+56M5LpKv
JFhRJwKBgEM3hwS5ljpW0tburNJJu1NRyjkXKTpoOKR2pP+z/af2QOAIG80/jQa5
UFP5MVXqH+wZI4Qv31BzM3c6mM9qpUxomyr7PUJ4bUkbjGAM/cG/rzA6PL55xhva
KFFnEWU62tBn0WlET/cOZG/i9bDN+5fQzdz6sxLh3E1JqLG6ZOYO
-----END RSA PRIVATE KEY-----
EOD;
    }

    public function testMalformedJWT()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
        ));

        //Get the jwt and break it
        $jwt = $this->getJWT();
        $jwt = substr_replace($jwt, 'broken', 3, 6);

        $request->request['assertion'] = $jwt;

        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'JWT is malformed');
    }

    public function testBrokenSignature()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
        ));

        //Get the jwt and break signature
        $jwt = $this->getJWT() . 'notSupposeToBeHere';
        $request->request['assertion'] = $jwt;

        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'JWT failed signature verification');
    }

    public function testExpiredJWT()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
        ));

        //Get an expired JWT
        $jwt = $this->getJWT(1234);
        $request->request['assertion'] = $jwt;

        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'JWT has expired');
    }

    public function testBadExp()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
        ));

        //Get an expired JWT
        $jwt = $this->getJWT('badtimestamp');
        $request->request['assertion'] = $jwt;

        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Expiration (exp) time must be a unix time stamp');
    }

    public function testNoAssert()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
        ));

        //Do not pass the assert (JWT)

        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'Missing parameters: "assertion" required');
    }

    public function testNotBefore()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
        ));

        //Get a future NBF
        $jwt = $this->getJWT(null, time() + 10000);
        $request->request['assertion'] = $jwt;

        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'JWT cannot be used before the Not Before (nbf) time');
    }

    public function testBadNotBefore()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
        ));

        //Get a non timestamp nbf
        $jwt = $this->getJWT(null, 'notatimestamp');
        $request->request['assertion'] = $jwt;

        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Not Before (nbf) time must be a unix time stamp');
    }

    public function testNonMatchingAudience()
    {
        $server = $this->getTestServer('http://google.com/oauth/o/auth');
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
            'assertion' => $this->getJWT(),
        ));

        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid audience (aud)');
    }

    public function testBadClientID()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',  // valid grant type
            'assertion' => $this->getJWT(null, null, null, 'bad_client_id'),
        ));

        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid issuer (iss) or subject (sub) provided');
    }

    public function testBadSubject()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',  // valid grant type
            'assertion' => $this->getJWT(null, null, 'anotheruser@ourdomain,com'),
        ));

        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid issuer (iss) or subject (sub) provided');
    }

    public function testMissingKey()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',  // valid grant type
            'assertion' => $this->getJWT(null, null, null, 'Missing Key Cli,nt'),
        ));

        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid issuer (iss) or subject (sub) provided');
    }

    public function testValidJwt()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',  // valid grant type
            'assertion' => $this->getJWT(), // valid assertion
        ));

        $token = $server->grantAccessToken($request, new Response());
        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
    }

    public function testValidJwtWithScope()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',  // valid grant type
            'assertion'  => $this->getJWT(null, null, null, 'Test Client ID'), // valid assertion
            'scope'      => 'scope1', // valid scope
        ));
        $token = $server->grantAccessToken($request, new Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('scope', $token);
        $this->assertEquals($token['scope'], 'scope1');
    }

    public function testValidJwtInvalidScope()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',  // valid grant type
            'assertion'  => $this->getJWT(null, null, null, 'Test Client ID'), // valid assertion
            'scope'      => 'invalid-scope', // invalid scope
        ));
        $token = $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_scope');
        $this->assertEquals($response->getParameter('error_description'), 'An unsupported scope was requested');
    }

    public function testValidJti()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',  // valid grant type
            'assertion' => $this->getJWT(null, null, 'testuser@ourdomain.com', 'Test Client ID', 'unused_jti'), // valid assertion with invalid scope
        ));
        $token = $server->grantAccessToken($request, $response = new Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
    }

    public function testInvalidJti()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',  // valid grant type
            'assertion' => $this->getJWT(99999999900, null, 'testuser@ourdomain.com', 'Test Client ID', 'used_jti'), // valid assertion with invalid scope
        ));
        $token = $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'JSON Token Identifier (jti) has already been used');
    }

    public function testJtiReplayAttack()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',  // valid grant type
            'assertion' => $this->getJWT(99999999900, null, 'testuser@ourdomain.com', 'Test Client ID', 'totally_new_jti'), // valid assertion with invalid scope
        ));
        $token = $server->grantAccessToken($request, $response = new Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);

        //Replay the same request
        $token = $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'JSON Token Identifier (jti) has already been used');
    }

    /**
     * Generates a JWT
     * @param $exp The expiration date. If the current time is greater than the exp, the JWT is invalid.
     * @param $nbf The "not before" time. If the current time is less than the nbf, the JWT is invalid.
     * @param $sub The subject we are acting on behalf of. This could be the email address of the user in the system.
     * @param $iss The issuer, usually the client_id.
     * @return string
     */
    private function getJWT($exp = null, $nbf = null, $sub = null, $iss = 'Test Client ID', $jti = null)
    {
        if (!$exp) {
            $exp = time() + 1000;
        }

        if (!$sub) {
            $sub = "testuser@ourdomain.com";
        }

        $params = array(
            'iss' => $iss,
            'exp' => $exp,
            'iat' => time(),
            'sub' => $sub,
            'aud' => 'http://myapp.com/oauth/auth',
        );

        if ($nbf) {
            $params['nbf'] = $nbf;
        }

        if ($jti) {
            $params['jti'] = $jti;
        }

        $jwtUtil = new Jwt();

        return $jwtUtil->encode($params, $this->privateKey, 'RS256');
    }

    private function getTestServer($audience = 'http://myapp.com/oauth/auth')
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage);
        $server->addGrantType(new JwtBearer($storage, $audience, new Jwt()));

        return $server;
    }
}
