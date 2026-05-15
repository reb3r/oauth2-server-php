<?php

namespace OAuth2\Encryption;

use OAuth2\Storage\Bootstrap;
use PHPUnit\Framework\TestCase;

class FirebaseJwtTest extends TestCase
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

    /** @dataProvider provideClientCredentials */
    public function testJwtUtil($client_id, $client_key)
    {
        $jwtUtil = new FirebaseJwt();

        $params = array(
            'iss' => $client_id,
            'exp' => time() + 1000,
            'iat' => time(),
            'sub' => 'testuser@ourdomain.com',
            'aud' => 'http://myapp.com/oauth/auth',
            'scope' => null,
        );

        $encoded = $jwtUtil->encode($params, $this->privateKey, 'RS256');

        // test BC behaviour of trusting the algorithm in the header
        $payload = $jwtUtil->decode($encoded, $client_key, array('RS256'));
        $this->assertEquals($params, $payload);

        // test BC behaviour of not verifying by passing false
        $payload = $jwtUtil->decode($encoded, $client_key, false);
        $this->assertEquals($params, $payload);

        // test the new restricted algorithms header
        $payload = $jwtUtil->decode($encoded, $client_key, array('RS256'));
        $this->assertEquals($params, $payload);
    }

    public function testInvalidJwt()
    {
        $jwtUtil = new FirebaseJwt();

        $this->assertFalse($jwtUtil->decode('goob'));
        $this->assertFalse($jwtUtil->decode('go.o.b'));
    }

    /** @dataProvider provideClientCredentials */
    public function testInvalidJwtHeader($client_id, $client_key)
    {
        $jwtUtil = new FirebaseJwt();

        $params = array(
            'iss' => $client_id,
            'exp' => time() + 1000,
            'iat' => time(),
            'sub' => 'testuser@ourdomain.com',
            'aud' => 'http://myapp.com/oauth/auth',
            'scope' => null,
        );

        // testing for algorithm tampering when only RSA256 signing is allowed
        // @see https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
        $tampered = $jwtUtil->encode($params, $client_key, 'HS256');

        $payload = $jwtUtil->decode($tampered, $client_key, array('RS256'));

        $this->assertFalse($payload);
    }

    public static function provideClientCredentials()
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $client_id  = 'Test Client ID';
        $client_key = $storage->getClientKey($client_id, "testuser@ourdomain.com");

        return array(
            array($client_id, $client_key),
        );
    }
}
