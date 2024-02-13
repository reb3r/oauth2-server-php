<?php

namespace OAuth2;

use OAuth2\ClientAssertionType\ClientAssertionTypeInterface;
use OAuth2\ClientAssertionType\HttpBasic;
use OAuth2\Controller\AuthorizeController;
use OAuth2\Controller\AuthorizeControllerInterface;
use OAuth2\Controller\ResourceController;
use OAuth2\Controller\ResourceControllerInterface;
use OAuth2\Controller\TokenController;
use OAuth2\Controller\TokenControllerInterface;
use OAuth2\GrantType\AuthorizationCode;
use OAuth2\GrantType\ClientCredentials;
use OAuth2\GrantType\GrantTypeInterface;
use OAuth2\GrantType\RefreshToken;
use OAuth2\GrantType\UserCredentials;
use OAuth2\OpenID\Controller\AuthorizeController as OpenIDAuthorizeController;
use OAuth2\OpenID\Controller\DiscoveryController;
use OAuth2\OpenID\Controller\JWKSetController;
use OAuth2\OpenID\Controller\JWKSetControllerInterface;
use OAuth2\OpenID\Controller\UserInfoController;
use OAuth2\OpenID\Controller\UserInfoControllerInterface;
use OAuth2\OpenID\GrantType\AuthorizationCode as OpenIDAuthorizationCodeGrantType;
use OAuth2\OpenID\ResponseType\AuthorizationCode as OpenIDAuthorizationCodeResponseType;
use OAuth2\OpenID\ResponseType\CodeIdToken;
use OAuth2\OpenID\ResponseType\IdToken;
use OAuth2\OpenID\ResponseType\IdTokenToken;
use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;
use OAuth2\ResponseType\AccessToken;
use OAuth2\ResponseType\AuthorizationCode as AuthorizationCodeResponseType;
use OAuth2\ResponseType\JwtAccessToken;
use OAuth2\ResponseType\ResponseTypeInterface;
use OAuth2\Storage\ClientCredentialsInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\Storage\JwtAccessToken as JwtAccessTokenStorage;
use OAuth2\Storage\JwtAccessTokenInterface;
use OAuth2\TokenType\Bearer;
use OAuth2\TokenType\TokenTypeInterface;
use LogicException;
use OAuth2\OpenID\Controller\DiscoveryControllerInterface;
use OAuth2\OpenID\Controller\LogoutController;
use OAuth2\OpenID\Controller\LogoutControllerInterface;
use OAuth2\OpenID\RequestType\LogoutToken;
use OAuth2\OpenID\RequestType\RequestTypeInterface;

/**
 * Server class for OAuth2
 * This class serves as a convience class which wraps the other Controller classes
 *
 * @see \OAuth2\Controller\ResourceController
 * @see \OAuth2\Controller\AuthorizeController
 * @see \OAuth2\Controller\TokenController
 */
class Server implements ResourceControllerInterface, AuthorizeControllerInterface, TokenControllerInterface, UserInfoControllerInterface, JWKSetControllerInterface, DiscoveryControllerInterface
{

    /**
     *
     * @var ResponseInterface
     */
    protected $response;

    /**
     *
     * @var array
     */
    protected $config;

    /**
     *
     * @var array
     */
    protected $storages;

    /**
     *
     * @var AuthorizeControllerInterface
     */
    protected $authorizeController;

    /**
     *
     * @var TokenControllerInterface
     */
    protected $tokenController;

    /**
     *
     * @var ResourceControllerInterface
     */
    protected $resourceController;

    /**
     *
     * @var UserInfoControllerInterface
     */
    protected $userInfoController;

    /**
     *
     * @var JWKSetControllerInterface
     */
    protected $jwkSetController;


    /**
     *
     * @var DiscoveryControllerInterface
     */
    protected $discoveryController;

    /**
     *
     * @var LogoutControllerInterface
     */
    protected $logoutController;

    /**
     *
     * @var array
     */
    protected $grantTypes = array();

    /**
     *
     * @var array
     */
    protected $responseTypes = array();

    /**
     *
     * @var array
     */
    protected $requestTypes = array();

    /**
     *
     * @var TokenTypeInterface
     */
    protected $tokenType;

    /**
     *
     * @var ScopeInterface
     */
    protected $scopeUtil;

    /**
     *
     * @var ClientAssertionTypeInterface
     */
    protected $clientAssertionType;

    /**
     *
     * @var array
     */
    protected $storageMap = array(
        'access_token' => 'OAuth2\Storage\AccessTokenInterface',
        'authorization_code' => 'OAuth2\Storage\AuthorizationCodeInterface',
        'client_credentials' => 'OAuth2\Storage\ClientCredentialsInterface',
        'client' => 'OAuth2\Storage\ClientInterface',
        'refresh_token' => 'OAuth2\Storage\RefreshTokenInterface',
        'user_credentials' => 'OAuth2\Storage\UserCredentialsInterface',
        'user_claims' => 'OAuth2\OpenID\Storage\UserClaimsInterface',
        'public_key' => 'OAuth2\Storage\PublicKeyInterface',
        'jwt_bearer' => 'OAuth2\Storage\JWTBearerInterface',
        'scope' => 'OAuth2\Storage\ScopeInterface',
        'discovery_configuration' => 'OAuth2\OpenID\Storage\DiscoveryConfigurationInterface',
        'session' => 'OAuth2\OpenID\Storage\SessionInterface',
        'session_token' => 'OAuth2\OpenID\Storage\SessionTokenInterface',
        'logged_in_rp' => 'OAuth2\OpenID\Storage\LoggedInRPInterface'
    );

    /**
     *
     * @var array
     */
    protected $responseTypeMap = array(
        'token' => 'OAuth2\ResponseType\AccessTokenInterface',
        'code' => 'OAuth2\ResponseType\AuthorizationCodeInterface',
        'id_token' => 'OAuth2\OpenID\ResponseType\IdTokenInterface',
        'id_token token' => 'OAuth2\OpenID\ResponseType\IdTokenTokenInterface',
        'code id_token' => 'OAuth2\OpenID\ResponseType\CodeIdTokenInterface'
    );

    /**
     *
     * @var array
     */
    protected $requestTypeMap = array(
        'logout_token' => 'OAuth2\OpenID\RequestType\LogoutTokenInterface'
    );

    /**
     *
     * @param mixed $storage
     *            (array or OAuth2\Storage) - single object or array of objects implementing the
     *            required storage types (ClientCredentialsInterface and AccessTokenInterface as a minimum)
     * @param array $config
     *            specify a different token lifetime, token header name, etc
     * @param array $grantTypes
     *            An array of OAuth2\GrantType\GrantTypeInterface to use for granting access tokens
     * @param array $responseTypes
     *            Response types to use. array keys should be "code" and "token" for
     *            Access Token and Authorization Code response types
     * @param TokenTypeInterface $tokenType
     *            The token type object to use. Valid token types are "bearer" and "mac"
     * @param ScopeInterface $scopeUtil
     *            The scope utility class to use to validate scope
     * @param ClientAssertionTypeInterface $clientAssertionType
     *            The method in which to verify the client identity. Default is HttpBasic
     *
     * @ingroup oauth2_section_7
     */
    public function __construct($storage = array(), array $config = array(), array $grantTypes = array(), array $responseTypes = array(), TokenTypeInterface $tokenType = null, ScopeInterface $scopeUtil = null, ClientAssertionTypeInterface $clientAssertionType = null)
    {
        $storage = is_array($storage) ? $storage : array(
            $storage
        );
        $this->storages = array();
        foreach ($storage as $key => $service) {
            $this->addStorage($service, $key);
        }

        // merge all config values. These get passed to our controller objects
        $this->config = array_merge(array(
            'use_jwt_access_tokens' => false,
            'jwt_extra_payload_callable' => null,
            'store_encrypted_token_string' => true,
            'use_openid_connect' => false,
            'id_lifetime' => 3600,
            'access_lifetime' => 3600,
            'www_realm' => 'Service',
            'token_param_name' => 'access_token',
            'token_bearer_header_name' => 'Bearer',
            'enforce_state' => true,
            'require_exact_redirect_uri' => true,
            'allow_implicit' => false,
            'enforce_pkce' => false,
            'allow_credentials_in_request_body' => true,
            'allow_public_clients' => true,
            'always_issue_new_refresh_token' => false,
            'unset_refresh_token_after_use' => true,
            'session_lifetime' => 3600,
        ), $config);

        foreach ($grantTypes as $key => $grantType) {
            $this->addGrantType($grantType, $key);
        }

        foreach ($responseTypes as $key => $responseType) {
            $this->addResponseType($responseType, $key);
        }

        $this->tokenType = $tokenType;
        $this->scopeUtil = $scopeUtil;
        $this->clientAssertionType = $clientAssertionType;

        if ($this->config['use_openid_connect']) {
            $this->validateOpenIdConnect();
        }
    }

    /**
     *
     * @return AuthorizeControllerInterface
     */
    public function getAuthorizeController()
    {
        if (is_null($this->authorizeController)) {
            $this->authorizeController = $this->createDefaultAuthorizeController();
        }

        return $this->authorizeController;
    }

    /**
     *
     * @return TokenController
     */
    public function getTokenController()
    {
        if (is_null($this->tokenController)) {
            $this->tokenController = $this->createDefaultTokenController();
        }

        return $this->tokenController;
    }

    /**
     *
     * @return ResourceControllerInterface
     */
    public function getResourceController()
    {
        if (is_null($this->resourceController)) {
            $this->resourceController = $this->createDefaultResourceController();
        }

        return $this->resourceController;
    }

    /**
     *
     * @return UserInfoControllerInterface
     */
    public function getUserInfoController()
    {
        if (is_null($this->userInfoController)) {
            $this->userInfoController = $this->createDefaultUserInfoController();
        }

        return $this->userInfoController;
    }

    /**
     *
     * @return JWKSetController
     */
    public function getJWKSetController()
    {
        if (is_null($this->jwkSetController)) {
            $this->jwkSetController = $this->createDefaultJWKSetController();
        }
        return $this->jwkSetController;
    }

    /**
     *
     * @return DiscoveryController
     */
    public function getDiscoveryController()
    {
        if (is_null($this->discoveryController)) {
            $this->discoveryController = $this->createDefaultDiscoveryController();
        }
        return $this->discoveryController;
    }

    /**
     *
     * @return LogoutController
     */
    public function getLogoutController()
    {
        if (is_null($this->logoutController)) {
            $this->logoutController = $this->createDefaultLogoutController();
        }
        return $this->logoutController;
    }

    /**
     *
     * @param AuthorizeControllerInterface $authorizeController
     */
    public function setAuthorizeController(AuthorizeControllerInterface $authorizeController)
    {
        $this->authorizeController = $authorizeController;
    }

    /**
     *
     * @param TokenControllerInterface $tokenController
     */
    public function setTokenController(TokenControllerInterface $tokenController)
    {
        $this->tokenController = $tokenController;
    }

    /**
     *
     * @param ResourceControllerInterface $resourceController
     */
    public function setResourceController(ResourceControllerInterface $resourceController)
    {
        $this->resourceController = $resourceController;
    }

    /**
     *
     * @param UserInfoControllerInterface $userInfoController
     */
    public function setUserInfoController(UserInfoControllerInterface $userInfoController)
    {
        $this->userInfoController = $userInfoController;
    }

    /**
     *
     * @param JWKSetController $jwkController
     */
    public function setJWKController(JWKSetControllerInterface $jwkSetController)
    {
        $this->jwkSetController = $jwkSetController;
    }

    /**
     *
     * @param DiscoveryControllerInterface $discoveryController
     */
    public function setDiscoveryController(DiscoveryControllerInterface $discoveryController)
    {
        $this->discoveryController = $discoveryController;
    }

    /**
     *
     * @param LogoutControllerInterface $logoutController
     */
    public function setLogoutController(LogoutControllerInterface $logoutController)
    {
        $this->logoutController = $logoutController;
    }

    /**
     * Return claims about the authenticated end-user.
     * This would be called from the "/UserInfo" endpoint as defined in the spec.
     *
     * @param RequestInterface $request
     *            - Request object to grant access token
     * @param ResponseInterface $response
     *            - Response object containing error messages (failure) or user claims (success)
     * @return ResponseInterface
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @see http://openid.net/specs/openid-connect-core-1_0.html#UserInfo
     */
    public function handleUserInfoRequest(RequestInterface $request, ResponseInterface $response = null)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $this->getUserInfoController()->handleUserInfoRequest($request, $this->response);

        return $this->response;
    }

    /**
     * Grant or deny a requested access token.
     * This would be called from the "/token" endpoint as defined in the spec.
     * Obviously, you can call your endpoint whatever you want.
     *
     * @param RequestInterface $request
     *            - Request object to grant access token
     * @param ResponseInterface $response
     *            - Response object containing error messages (failure) or access token (success)
     * @return ResponseInterface
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4
     * @see http://tools.ietf.org/html/rfc6749#section-10.6
     * @see http://tools.ietf.org/html/rfc6749#section-4.1.3
     *
     * @ingroup oauth2_section_4
     */
    public function handleTokenRequest(RequestInterface $request, ResponseInterface $response = null, $session_id = null)
    {
        $this->response = is_null($response) ? new Response() : $response;

        $token = $this->getTokenController()->handleTokenRequest($request, $this->response);

        if ($this->isBackchannelLogoutSupported() && $token) {
            $this->getLogoutController()->setHandleTokenSession($request, $token);
        }

        return $this->response;
    }

    /**
     * Decodes the id token of openid
     *
     * @param string $token
     * @return mixed
     */
    public function getDecodedIdToken(string $token)
    {
        return $this->getIdTokenResponseType()->decodeToken($token);
    }

    /**
     * Handles the validate rp logout request
     *
     * @param RequestInterface $request
     * @param ResponseInterface|null $response
     * @return boolean
     * 
     * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling
     */
    public function handleValidateRPLogoutRequest(RequestInterface $request, ResponseInterface $response = null)
    {
        return $this->getLogoutController()->validateRPLogoutRequest($request, $response);
    }

    /**
     *
     * @param RequestInterface $request
     *            - Request object to grant access token
     * @param ResponseInterface $response
     *            - Response object
     * @return mixed
     */
    public function grantAccessToken(RequestInterface $request, ResponseInterface $response = null)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $value = $this->getTokenController()->grantAccessToken($request, $this->response);

        return $value;
    }

    /**
     * Handle a revoke token request
     * This would be called from the "/revoke" endpoint as defined in the draft Token Revocation spec
     *
     * @see https://tools.ietf.org/html/rfc7009#section-2
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return Response|ResponseInterface
     */
    public function handleRevokeRequest(RequestInterface $request, ResponseInterface $response = null)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $this->getTokenController()->handleRevokeRequest($request, $this->response);

        return $this->response;
    }

    /**
     * Redirect the user appropriately after approval.
     *
     * After the user has approved or denied the resource request the
     * authorization server should call this function to redirect the user
     * appropriately.
     *
     * @param RequestInterface $request
     *            - The request should have the follow parameters set in the querystring:
     *            - response_type: The requested response: an access token, an authorization code, or both.
     *            - client_id: The client identifier as described in Section 2.
     *            - redirect_uri: An absolute URI to which the authorization server will redirect the user-agent to when the
     *            end-user authorization step is completed.
     *            - scope: (optional) The scope of the resource request expressed as a list of space-delimited strings.
     *            - state: (optional) An opaque value used by the client to maintain state between the request and callback.
     *
     * @param ResponseInterface $response
     *            - Response object
     * @param bool $is_authorized
     *            - TRUE or FALSE depending on whether the user authorized the access.
     * @param mixed $user_id
     *            - Identifier of user who authorized the client
     * @return ResponseInterface
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4
     *
     * @ingroup oauth2_section_4
     */
    public function handleAuthorizeRequest(RequestInterface $request, ResponseInterface $response, $is_authorized, $user_id = null, $session_id = null)
    {
        $this->response = $response;

        $sid = null;
        // set session for backchannel logout if config is set
        if ($this->isBackchannelLogoutSupported() && $user_id && $session_id) {
            $session = $this->getLogoutController()->setSession($session_id, $user_id);
            $sid = $session['sid'] ?? null;
        }
        
        $this->getAuthorizeController()->handleAuthorizeRequest($request, $this->response, $is_authorized, $user_id, $sid);

        return $this->response;
    }

    /**
     * Pull the authorization request data out of the HTTP request.
     * - The redirect_uri is OPTIONAL as per draft 20. But your implementation can enforce it
     * by setting $config['enforce_redirect'] to true.
     * - The state is OPTIONAL but recommended to enforce CSRF. Draft 21 states, however, that
     * CSRF protection is MANDATORY. You can enforce this by setting the $config['enforce_state'] to true.
     *
     * The draft specifies that the parameters should be retrieved from GET, override the Response
     * object to change this
     *
     * @param RequestInterface $request
     *            - Request object
     * @param ResponseInterface $response
     *            - Response object
     * @return bool The authorization parameters so the authorization server can prompt
     *         the user for approval if valid.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4.1.1
     * @see http://tools.ietf.org/html/rfc6749#section-10.12
     *
     * @ingroup oauth2_section_3
     */
    public function validateAuthorizeRequest(RequestInterface $request, ResponseInterface $response = null)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $value = $this->getAuthorizeController()->validateAuthorizeRequest($request, $this->response);

        return $value;
    }

    public function handleJWKSetRequest(RequestInterface $request, ResponseInterface $response)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $this->getJWKSetController()->handleJWKSetRequest($request, $response);

        return $this->response;
    }

    public function validateJWKSetRequest(RequestInterface $request, ResponseInterface $response)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $value = $this->getJWKSetController()->validateJWKSetRequest($request, $response);

        return $value;
    }

    public function handleConfigurationDiscoveryRequest(RequestInterface $request, ResponseInterface $response)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $this->getDiscoveryController()->handleConfigurationDiscoveryRequest($request, $response);

        return $this->response;
    }

    public function validateConfigurationDiscoveryRequest(RequestInterface $request, ResponseInterface $response)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $value = $this->getDiscoveryController()->validateConfigurationDiscoveryRequest($request, $response);

        return $value;
    }

    /**
     * Logout the user from all logged in rps
     * 
     *
     * @param LogInterface $log
     * @param string $session_id
     *            - Session identifier of the application
     * @param mixed $user_id
     *            - Identifier of user who authorized the client
     * @return bool
     * 
     * @see https://openid.net/specs/openid-connect-backchannel-1_0.html#Backchannel
     */
    public function handleLogoutSession(LogInterface $log, $session_id, $user_id = null)
    {
        return $this->getLogoutController()->handleLogoutSession($log, $session_id, $user_id);
    }

    /**
     * Logout the user from a certain rp
     *
     * @param LogInterface $log
     * @param string $client_id
     * @param string $session_id
     *            - Session identifier of the application
     * @return bool
     * 
     * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
     */
    public function handleLogoutRP(LogInterface $log, $client_id, $session_id)
    {
        return $this->getLogoutController()->handleLogoutRP($log, $client_id, $session_id);
    }

    /**
     *
     * @param RequestInterface $request
     *            - Request object
     * @param ResponseInterface $response
     *            - Response object
     * @param string $scope
     *            - Scope
     * @return mixed
     */
    public function verifyResourceRequest(RequestInterface $request, ResponseInterface $response = null, $scope = null)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $value = $this->getResourceController()->verifyResourceRequest($request, $this->response, $scope);

        return $value;
    }

    /**
     *
     * @param RequestInterface $request
     *            - Request object
     * @param ResponseInterface $response
     *            - Response object
     * @return mixed
     */
    public function getAccessTokenData(RequestInterface $request, ResponseInterface $response = null)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $value = $this->getResourceController()->getAccessTokenData($request, $this->response);

        return $value;
    }

    /**
     *
     * @param GrantTypeInterface $grantType
     * @param mixed $identifier
     */
    public function addGrantType(GrantTypeInterface $grantType, $identifier = null)
    {
        if (!is_string($identifier)) {
            $identifier = $grantType->getQueryStringIdentifier();
        }

        $this->grantTypes[$identifier] = $grantType;

        // persist added grant type down to TokenController
        if (!is_null($this->tokenController)) {
            $this->getTokenController()->addGrantType($grantType, $identifier);
        }
    }

    /**
     * Set a storage object for the server
     *
     * @param object $storage
     *            - An object implementing one of the Storage interfaces
     * @param mixed $key
     *            - If null, the storage is set to the key of each storage interface it implements
     *
     * @throws InvalidArgumentException
     * @see storageMap
     */
    public function addStorage($storage, $key = null)
    {
        // if explicitly set to a valid key, do not "magically" set below
        if (isset($this->storageMap[$key])) {
            if (!is_null($storage) && !$storage instanceof $this->storageMap[$key]) {
                throw new \InvalidArgumentException(sprintf('storage of type "%s" must implement interface "%s"', $key, $this->storageMap[$key]));
            }
            $this->storages[$key] = $storage;

            // special logic to handle "client" and "client_credentials" strangeness
            if ($key === 'client' && !isset($this->storages['client_credentials'])) {
                if ($storage instanceof ClientCredentialsInterface) {
                    $this->storages['client_credentials'] = $storage;
                }
            } elseif ($key === 'client_credentials' && !isset($this->storages['client'])) {
                if ($storage instanceof ClientInterface) {
                    $this->storages['client'] = $storage;
                }
            }
        } elseif (!is_null($key) && !is_numeric($key)) {
            throw new \InvalidArgumentException(sprintf('unknown storage key "%s", must be one of [%s]', $key, implode(', ', array_keys($this->storageMap))));
        } else {
            $set = false;
            foreach ($this->storageMap as $type => $interface) {
                if ($storage instanceof $interface) {
                    $this->storages[$type] = $storage;
                    $set = true;
                }
            }

            if (!$set) {
                throw new \InvalidArgumentException(sprintf('storage of class "%s" must implement one of [%s]', get_class($storage), implode(', ', $this->storageMap)));
            }
        }
    }

    /**
     *
     * @param ResponseTypeInterface $responseType
     * @param mixed $key
     *
     * @throws InvalidArgumentException
     */
    public function addResponseType(ResponseTypeInterface $responseType, $key = null)
    {
        $key = $this->normalizeResponseType($key);

        if (isset($this->responseTypeMap[$key])) {
            if (!$responseType instanceof $this->responseTypeMap[$key]) {
                throw new \InvalidArgumentException(sprintf('responseType of type "%s" must implement interface "%s"', $key, $this->responseTypeMap[$key]));
            }
            $this->responseTypes[$key] = $responseType;
        } elseif (!is_null($key) && !is_numeric($key)) {
            throw new \InvalidArgumentException(sprintf('unknown responseType key "%s", must be one of [%s]', $key, implode(', ', array_keys($this->responseTypeMap))));
        } else {
            $set = false;
            foreach ($this->responseTypeMap as $type => $interface) {
                if ($responseType instanceof $interface) {
                    $this->responseTypes[$type] = $responseType;
                    $set = true;
                }
            }

            if (!$set) {
                throw new \InvalidArgumentException(sprintf('Unknown response type %s.  Please implement one of [%s]', get_class($responseType), implode(', ', $this->responseTypeMap)));
            }
        }
    }

    /**
     *
     * @param RequestTypeInterface $requestType
     * @param mixed $key
     *
     * @throws InvalidArgumentException
     */
    public function addRequestType(RequestTypeInterface $requestType, $key = null)
    {
        $key = $this->normalizeResponseType($key);

        if (isset($this->requestTypeMap[$key])) {
            if (!$requestType instanceof $this->requestTypeMap[$key]) {
                throw new \InvalidArgumentException(sprintf('responseType of type "%s" must implement interface "%s"', $key, $this->requestTypeMap[$key]));
            }
            $this->responseTypes[$key] = $requestType;
        } elseif (!is_null($key) && !is_numeric($key)) {
            throw new \InvalidArgumentException(sprintf('unknown responseType key "%s", must be one of [%s]', $key, implode(', ', array_keys($this->requestTypeMap))));
        } else {
            $set = false;
            foreach ($this->requestTypeMap as $type => $interface) {
                if ($requestType instanceof $interface) {
                    $this->responseTypes[$type] = $requestType;
                    $set = true;
                }
            }

            if (!$set) {
                throw new \InvalidArgumentException(sprintf('Unknown response type %s.  Please implement one of [%s]', get_class($requestType), implode(', ', $this->requestTypeMap)));
            }
        }
    }

    /**
     *
     * @return ScopeInterface
     */
    public function getScopeUtil()
    {
        if (!$this->scopeUtil) {
            $storage = isset($this->storages['scope']) ? $this->storages['scope'] : null;
            $this->scopeUtil = new Scope($storage);
        }

        return $this->scopeUtil;
    }

    /**
     *
     * @param ScopeInterface $scopeUtil
     */
    public function setScopeUtil($scopeUtil)
    {
        $this->scopeUtil = $scopeUtil;
    }

    /**
     *
     * @return AuthorizeControllerInterface
     * @throws LogicException
     */
    protected function createDefaultAuthorizeController()
    {
        if (!isset($this->storages['client'])) {
            throw new \LogicException('You must supply a storage object implementing \OAuth2\Storage\ClientInterface to use the authorize server');
        }
        if (0 == count($this->responseTypes)) {
            $this->responseTypes = $this->getDefaultResponseTypes();
        }
        if ($this->config['use_openid_connect'] && !isset($this->responseTypes['id_token'])) {
            $this->responseTypes['id_token'] = $this->createDefaultIdTokenResponseType();
            if ($this->config['allow_implicit']) {
                $this->responseTypes['id_token token'] = $this->createDefaultIdTokenTokenResponseType();
            }
        }

        $config = array_intersect_key($this->config, array_flip(explode(' ', 'allow_implicit enforce_state require_exact_redirect_uri enforce_pkce')));

        if ($this->config['use_openid_connect']) {
            return new OpenIDAuthorizeController($this->storages['client'], $this->responseTypes, $config, $this->getScopeUtil());
        }

        return new AuthorizeController($this->storages['client'], $this->responseTypes, $config, $this->getScopeUtil());
    }

    /**
     *
     * @return TokenControllerInterface
     * @throws LogicException
     */
    protected function createDefaultTokenController()
    {
        if (0 == count($this->grantTypes)) {
            $this->grantTypes = $this->getDefaultGrantTypes();
        }

        if (is_null($this->clientAssertionType)) {
            // see if HttpBasic assertion type is requred. If so, then create it from storage classes.
            foreach ($this->grantTypes as $grantType) {
                if (!$grantType instanceof ClientAssertionTypeInterface) {
                    if (!isset($this->storages['client_credentials'])) {
                        throw new \LogicException('You must supply a storage object implementing OAuth2\Storage\ClientCredentialsInterface to use the token server');
                    }
                    $config = array_intersect_key($this->config, array_flip(explode(' ', 'allow_credentials_in_request_body allow_public_clients')));
                    $this->clientAssertionType = new HttpBasic($this->storages['client_credentials'], $config);
                    break;
                }
            }
        }

        if (!isset($this->storages['client'])) {
            throw new LogicException("You must supply a storage object implementing OAuth2\Storage\ClientInterface to use the token server");
        }

        $accessTokenResponseType = $this->getAccessTokenResponseType();

        return new TokenController($accessTokenResponseType, $this->storages['client'], $this->grantTypes, $this->clientAssertionType, $this->getScopeUtil());
    }

    /**
     *
     * @return ResourceControllerInterface
     * @throws LogicException
     */
    protected function createDefaultResourceController()
    {
        if ($this->config['use_jwt_access_tokens']) {
            // overwrites access token storage with crypto token storage if "use_jwt_access_tokens" is set
            if (!isset($this->storages['access_token']) || !$this->storages['access_token'] instanceof JwtAccessTokenInterface) {
                $this->storages['access_token'] = $this->createDefaultJwtAccessTokenStorage();
            }
        } elseif (!isset($this->storages['access_token'])) {
            throw new \LogicException('You must supply a storage object implementing OAuth2\Storage\AccessTokenInterface or use JwtAccessTokens to use the resource server');
        }

        if (!$this->tokenType) {
            $this->tokenType = $this->getDefaultTokenType();
        }

        $config = array_intersect_key($this->config, array(
            'www_realm' => ''
        ));

        return new ResourceController($this->tokenType, $this->storages['access_token'], $config, $this->getScopeUtil());
    }

    /**
     *
     * @return UserInfoControllerInterface
     * @throws LogicException
     */
    protected function createDefaultUserInfoController()
    {
        if ($this->config['use_jwt_access_tokens']) {
            // overwrites access token storage with crypto token storage if "use_jwt_access_tokens" is set
            if (!isset($this->storages['access_token']) || !$this->storages['access_token'] instanceof JwtAccessTokenInterface) {
                $this->storages['access_token'] = $this->createDefaultJwtAccessTokenStorage();
            }
        } elseif (!isset($this->storages['access_token'])) {
            throw new \LogicException('You must supply a storage object implementing OAuth2\Storage\AccessTokenInterface or use JwtAccessTokens to use the UserInfo server');
        }

        if (!isset($this->storages['user_claims'])) {
            throw new \LogicException('You must supply a storage object implementing OAuth2\OpenID\Storage\UserClaimsInterface to use the UserInfo server');
        }

        if (!$this->tokenType) {
            $this->tokenType = $this->getDefaultTokenType();
        }

        $config = array_intersect_key($this->config, array(
            'www_realm' => ''
        ));

        return new UserInfoController($this->tokenType, $this->storages['access_token'], $this->storages['user_claims'], $config, $this->getScopeUtil());
    }

    protected function createDefaultJWKSetController()
    {
        return new JWKSetController($this->storages['public_key']);
    }

    protected function createDefaultDiscoveryController()
    {
        return new DiscoveryController($this->storages['discovery_configuration']);
    }

    /**
     * Undocumented function
     *
     * @return LogoutControllerInterface
     * @throws LogicException
     */
    protected function createDefaultLogoutController()
    {
        if (!isset($this->storages['session'])) {
            throw new LogicException("You must supply a storage object implementing \OAuth2\OpenID\Storage\SessionInterface to use the session logout");
        }

        if (!isset($this->storages['logged_in_rp'])) {
            throw new LogicException("You must supply a storage object implementing \OAuth2\OpenID\Storage\LoggedInRPInterface to use the session logout");
        }

        if (!isset($this->storages['client'])) {
            throw new LogicException("You must supply a storage object implementing \OAuth2\Storage\ClientInterface to use the session logout");
        }

        if (!isset($this->storages['session_token'])) {
            throw new LogicException("You must supply a storage object implementing \OAuth2\OpenID\Storage\SessionTokenInterface to use the session logout");
        }

        $logoutTokenRequestType = $this->getLogoutTokenRequestType();
        $idTokenResponseType = $this->getIdTokenResponseType();

        return new LogoutController($this->storages['session'], $this->storages['logged_in_rp'], $this->storages['client'], $this->storages['session_token'], $logoutTokenRequestType, $idTokenResponseType, $this->grantTypes, $this->config);
    }

    /**
     *
     * @return Bearer
     */
    protected function getDefaultTokenType()
    {
        $config = array_intersect_key($this->config, array_flip(explode(' ', 'token_param_name token_bearer_header_name')));

        return new Bearer($config);
    }

    /**
     *
     * @return array
     * @throws LogicException
     */
    protected function getDefaultResponseTypes()
    {
        $responseTypes = array();

        if ($this->config['allow_implicit']) {
            $responseTypes['token'] = $this->getAccessTokenResponseType();
        }

        if ($this->config['use_openid_connect']) {
            $responseTypes['id_token'] = $this->getIdTokenResponseType();
            if ($this->config['allow_implicit']) {
                $responseTypes['id_token token'] = $this->getIdTokenTokenResponseType();
            }
        }

        if (isset($this->storages['authorization_code'])) {
            $config = array_intersect_key($this->config, array_flip(explode(' ', 'enforce_redirect auth_code_lifetime')));
            if ($this->config['use_openid_connect']) {
                if (!$this->storages['authorization_code'] instanceof OpenIDAuthorizationCodeInterface) {
                    throw new \LogicException('Your authorization_code storage must implement OAuth2\OpenID\Storage\AuthorizationCodeInterface to work when "use_openid_connect" is true');
                }
                $responseTypes['code'] = new OpenIDAuthorizationCodeResponseType($this->storages['authorization_code'], $config);
                $responseTypes['code id_token'] = new CodeIdToken($responseTypes['code'], $responseTypes['id_token']);
            } else {
                $responseTypes['code'] = new AuthorizationCodeResponseType($this->storages['authorization_code'], $config);
            }
        }

        if (count($responseTypes) == 0) {
            throw new \LogicException('You must supply an array of response_types in the constructor or implement a OAuth2\Storage\AuthorizationCodeInterface storage object or set "allow_implicit" to true and implement a OAuth2\Storage\AccessTokenInterface storage object');
        }

        return $responseTypes;
    }

    /**
     *
     * @return array
     * @throws LogicException
     */
    protected function getDefaultGrantTypes()
    {
        $grantTypes = array();

        if (isset($this->storages['user_credentials'])) {
            $grantTypes['password'] = new UserCredentials($this->storages['user_credentials']);
        }

        if (isset($this->storages['client_credentials'])) {
            $config = array_intersect_key($this->config, array(
                'allow_credentials_in_request_body' => ''
            ));
            $grantTypes['client_credentials'] = new ClientCredentials($this->storages['client_credentials'], $config);
        }

        if (isset($this->storages['refresh_token'])) {
            $config = array_intersect_key($this->config, array_flip(explode(' ', 'always_issue_new_refresh_token unset_refresh_token_after_use')));
            $grantTypes['refresh_token'] = new RefreshToken($this->storages['refresh_token'], $config);
        }

        if (isset($this->storages['authorization_code'])) {
            if ($this->config['use_openid_connect']) {
                if (!$this->storages['authorization_code'] instanceof OpenIDAuthorizationCodeInterface) {
                    throw new \LogicException('Your authorization_code storage must implement OAuth2\OpenID\Storage\AuthorizationCodeInterface to work when "use_openid_connect" is true');
                }
                $grantTypes['authorization_code'] = new OpenIDAuthorizationCodeGrantType($this->storages['authorization_code']);
            } else {
                $grantTypes['authorization_code'] = new AuthorizationCode($this->storages['authorization_code']);
            }
        }

        if (count($grantTypes) == 0) {
            throw new \LogicException('Unable to build default grant types - You must supply an array of grant_types in the constructor');
        }

        return $grantTypes;
    }

    /**
     *
     * @return AccessToken
     */
    protected function getAccessTokenResponseType()
    {
        if (isset($this->responseTypes['token'])) {
            return $this->responseTypes['token'];
        }

        if ($this->config['use_jwt_access_tokens']) {
            return $this->createDefaultJwtAccessTokenResponseType();
        }

        return $this->createDefaultAccessTokenResponseType();
    }

    /**
     *
     * @return IdToken
     */
    protected function getIdTokenResponseType()
    {
        if (isset($this->responseTypes['id_token'])) {
            return $this->responseTypes['id_token'];
        }

        return $this->createDefaultIdTokenResponseType();
    }

    /**
     *
     * @return IdTokenToken
     */
    protected function getIdTokenTokenResponseType()
    {
        if (isset($this->responseTypes['id_token token'])) {
            return $this->responseTypes['id_token token'];
        }

        return $this->createDefaultIdTokenTokenResponseType();
    }

    /**
     *
     * @return LogoutToken
     */
    protected function getLogoutTokenRequestType()
    {
        if (isset($this->requestTypes['logout_token'])) {
            return $this->requestTypes['logout_token'];
        }

        return $this->createDefaultLogoutTokenRequestType();
    }

    /**
     * For Resource Controller
     *
     * @return JwtAccessTokenStorage
     * @throws LogicException
     */
    protected function createDefaultJwtAccessTokenStorage()
    {
        if (!isset($this->storages['public_key'])) {
            throw new \LogicException('You must supply a storage object implementing OAuth2\Storage\PublicKeyInterface to use crypto tokens');
        }
        $tokenStorage = null;
        if (!empty($this->config['store_encrypted_token_string']) && isset($this->storages['access_token'])) {
            $tokenStorage = $this->storages['access_token'];
        }
        // wrap the access token storage as required.
        return new JwtAccessTokenStorage($this->storages['public_key'], $tokenStorage);
    }

    /**
     * For Authorize and Token Controllers
     *
     * @return JwtAccessToken
     * @throws LogicException
     */
    protected function createDefaultJwtAccessTokenResponseType()
    {
        if (!isset($this->storages['public_key'])) {
            throw new \LogicException('You must supply a storage object implementing OAuth2\Storage\PublicKeyInterface to use crypto tokens');
        }

        $tokenStorage = null;
        if (isset($this->storages['access_token'])) {
            $tokenStorage = $this->storages['access_token'];
        }

        $refreshStorage = null;
        if (isset($this->storages['refresh_token'])) {
            $refreshStorage = $this->storages['refresh_token'];
        }

        $config = array_intersect_key($this->config, array_flip(explode(' ', 'store_encrypted_token_string issuer access_lifetime refresh_token_lifetime jwt_extra_payload_callable')));

        return new JwtAccessToken($this->storages['public_key'], $tokenStorage, $refreshStorage, $config);
    }

    /**
     *
     * @return AccessToken
     * @throws LogicException
     */
    protected function createDefaultAccessTokenResponseType()
    {
        if (!isset($this->storages['access_token'])) {
            throw new LogicException("You must supply a response type implementing OAuth2\ResponseType\AccessTokenInterface, or a storage object implementing OAuth2\Storage\AccessTokenInterface to use the token server");
        }

        $refreshStorage = null;
        if (isset($this->storages['refresh_token'])) {
            $refreshStorage = $this->storages['refresh_token'];
        }

        $config = array_intersect_key($this->config, array_flip(explode(' ', 'access_lifetime refresh_token_lifetime')));
        $config['token_type'] = $this->tokenType ? $this->tokenType->getTokenType() : $this->getDefaultTokenType()->getTokenType();

        return new AccessToken($this->storages['access_token'], $refreshStorage, $config);
    }

    /**
     *
     * @return IdToken
     * @throws LogicException
     */
    protected function createDefaultIdTokenResponseType()
    {
        if (!isset($this->storages['user_claims'])) {
            throw new LogicException("You must supply a storage object implementing OAuth2\OpenID\Storage\UserClaimsInterface to use openid connect");
        }
        if (!isset($this->storages['public_key'])) {
            throw new LogicException("You must supply a storage object implementing OAuth2\Storage\PublicKeyInterface to use openid connect");
        }

        $config = array_intersect_key($this->config, array_flip(explode(' ', 'issuer id_lifetime')));

        return new IdToken($this->storages['user_claims'], $this->storages['public_key'], $config);
    }

    /**
     *
     * @return IdTokenToken
     */
    protected function createDefaultIdTokenTokenResponseType()
    {
        return new IdTokenToken($this->getAccessTokenResponseType(), $this->getIdTokenResponseType());
    }

    /**
     *
     * @return LogoutToken
     * @throws LogicException
     */
    protected function createDefaultLogoutTokenRequestType()
    {
        if (!isset($this->storages['user_claims'])) {
            throw new LogicException("You must supply a storage object implementing OAuth2\OpenID\Storage\UserClaimsInterface to use openid connect");
        }
        if (!isset($this->storages['public_key'])) {
            throw new LogicException("You must supply a storage object implementing OAuth2\Storage\PublicKeyInterface to use openid connect");
        }

        $config = array_intersect_key($this->config, array_flip(explode(' ', 'issuer id_lifetime')));

        return new LogoutToken($this->storages['user_claims'], $this->storages['public_key'], $config);
    }

    /**
     *
     * @throws InvalidArgumentException
     */
    protected function validateOpenIdConnect()
    {
        $authCodeGrant = $this->getGrantType('authorization_code');
        if (!empty($authCodeGrant) && !$authCodeGrant instanceof OpenIDAuthorizationCodeGrantType) {
            throw new \InvalidArgumentException('You have enabled OpenID Connect, but supplied a grant type that does not support it.');
        }
    }

    /**
     *
     * @param string $name
     * @return string
     */
    protected function normalizeResponseType($name)
    {
        // for multiple-valued response types - make them alphabetical
        if (!empty($name) && false !== strpos($name, ' ')) {
            $types = explode(' ', $name);
            sort($types);
            $name = implode(' ', $types);
        }

        return $name;
    }

    protected function isBackchannelLogoutSupported()
    {
        return (isset($this->config['discovery_configuration']['backchannel_logout_supported']) && $this->config['discovery_configuration']['backchannel_logout_supported'] === true);
    }

    /**
     *
     * @return mixed
     */
    public function getResponse()
    {
        return $this->response;
    }

    /**
     *
     * @return array
     */
    public function getStorages()
    {
        return $this->storages;
    }

    /**
     *
     * @param string $name
     * @return object|null
     */
    public function getStorage($name)
    {
        return isset($this->storages[$name]) ? $this->storages[$name] : null;
    }

    /**
     *
     * @return array
     */
    public function getGrantTypes()
    {
        return $this->grantTypes;
    }

    /**
     *
     * @param string $name
     * @return object|null
     */
    public function getGrantType($name)
    {
        return isset($this->grantTypes[$name]) ? $this->grantTypes[$name] : null;
    }

    /**
     *
     * @return array
     */
    public function getResponseTypes()
    {
        return $this->responseTypes;
    }

    /**
     *
     * @param string $name
     * @return object|null
     */
    public function getResponseType($name)
    {
        // for multiple-valued response types - make them alphabetical
        $name = $this->normalizeResponseType($name);

        return isset($this->responseTypes[$name]) ? $this->responseTypes[$name] : null;
    }

    /**
     *
     * @return TokenTypeInterface
     */
    public function getTokenType()
    {
        return $this->tokenType;
    }

    /**
     *
     * @return ClientAssertionTypeInterface
     */
    public function getClientAssertionType()
    {
        return $this->clientAssertionType;
    }

    /**
     *
     * @param string $name
     * @param mixed $value
     */
    public function setConfig($name, $value)
    {
        $this->config[$name] = $value;
    }

    /**
     *
     * @param string $name
     * @param mixed $default
     * @return mixed
     */
    public function getConfig($name, $default = null)
    {
        return isset($this->config[$name]) ? $this->config[$name] : $default;
    }
}
