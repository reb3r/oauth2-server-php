<?php

namespace OAuth2\OpenID\RequestType;

use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\OpenID\Storage\UserClaimsInterface;
use LogicException;
use OAuth2\OpenID\RequestType\LogoutTokenInterface;
use OAuth2\UniqueToken;

class LogoutToken implements LogoutTokenInterface
{
    /**
     * @var UserClaimsInterface
     */
    protected $userClaimsStorage;
    /**
     * @var PublicKeyInterface
     */
    protected $publicKeyStorage;

    /**
     * @var array
     */
    protected $config;

    /**
     * @var EncryptionInterface
     */
    protected $encryptionUtil;

    /**
     * Constructor
     *
     * @param UserClaimsInterface $userClaimsStorage
     * @param PublicKeyInterface $publicKeyStorage
     * @param array $config
     * @param EncryptionInterface $encryptionUtil
     * @throws LogicException
     */
    public function __construct(UserClaimsInterface $userClaimsStorage, PublicKeyInterface $publicKeyStorage, array $config = array(), EncryptionInterface $encryptionUtil = null)
    {
        $this->userClaimsStorage = $userClaimsStorage;
        $this->publicKeyStorage = $publicKeyStorage;
        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt();
        }
        $this->encryptionUtil = $encryptionUtil;

        if (!isset($config['issuer'])) {
            throw new LogicException('config parameter "issuer" must be set');
        }
        $this->config = array_merge(array(
            'logout_token_lifetime' => 3600,
        ), $config);
    }

    /**
     * Create logout token
     *
     * @param string $client_id
     * @param mixed  $user_id
     * @param mixed  $sid
     * 
     * @return mixed|string
     */
    public function createLogoutToken($client_id, $user_id = null, $sid = null)
    {
        $token = array(
            'iss'        => $this->config['issuer'],
            'aud'        => $client_id,
            'iat'        => time(),
            'jti'        => UniqueToken::uniqueToken(),
            'events'     => ['http://schemas.openid.net/event/backchannel-logout' => []],
            'exp'        => time() + $this->config['logout_token_lifetime'],
        );

        if (isset($user_id)) {
            $token['sub'] = $user_id;
        }

        if (isset($sid)) {
            $token['sid'] = $sid;
        }

        return $this->encodeToken($token, $client_id);
    }

    /**
     * @param array $token
     * @param null $client_id
     * @return mixed|string
     */
    protected function encodeToken(array $token, $client_id = null)
    {
        $private_key = $this->publicKeyStorage->getPrivateKey($client_id);
        $algorithm = $this->publicKeyStorage->getEncryptionAlgorithm($client_id);

        return $this->encryptionUtil->encode($token, $private_key, $algorithm);
    }
}
