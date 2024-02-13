<?php
namespace OAuth2\OpenID\Controller;

use GuzzleHttp\Client;
use OAuth2\GrantType\AuthorizationCode;
use OAuth2\GrantType\GrantTypeInterface;
use OAuth2\GrantType\RefreshToken;
use OAuth2\LogInterface;
use OAuth2\OpenID\RequestType\LogoutTokenInterface;
use OAuth2\OpenID\ResponseType\IdTokenInterface;
use OAuth2\OpenID\Storage\LoggedInRPInterface;
use OAuth2\OpenID\Storage\SessionInterface;
use OAuth2\OpenID\Storage\SessionTokenInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\UniqueToken;

class LogoutController implements LogoutControllerInterface
{

    /**
     * @var SessionInterface
     */
    protected $sessionStorage;

    /**
     * @var LoggedInRPInterface
     */
    protected $loggedInRPStorage;

    /**
     * @var ClientInterface
     */
    protected $clientStorage;

    /**
     * @var SessionTokenInterface
     */
    protected $sessionTokenStorage;

    /**
     * @var LogoutTokenInterface
     */
    protected $logoutToken;

    /**
     * @var array<GrantTypeInterface>
     */
    protected $grantTypes;

    /**
     * @var IdTokenInterface
     */
    protected $idToken;

    /**
     * @var array
     */
    protected $config;

    /**
     * @var Client
     */
    protected $httpClient;

    public function __construct(SessionInterface $sessionStorage, LoggedInRPInterface $loggedInRPStorage, ClientInterface $clientStorage, SessionTokenInterface $sessionTokenStorage, LogoutTokenInterface $logoutToken, IdTokenInterface $idToken, array $grantTypes = array(), array $config = array(), Client $httpClient = null)
    {
        $this->sessionStorage = $sessionStorage;
        $this->loggedInRPStorage = $loggedInRPStorage;
        $this->clientStorage = $clientStorage;
        $this->sessionTokenStorage = $sessionTokenStorage;
        $this->logoutToken = $logoutToken;

        foreach ($grantTypes as $grantType) {
            $this->addGrantType($grantType);
        }

        if (!$httpClient) {
            $this->httpClient = new Client();
        } else {
            $this->httpClient = $httpClient;
        }

        $this->config = $config;
        $this->idToken = $idToken;
    }

    /**
     * Handle the complete session logout
     *
     * @param LogInterface $log
     * @param string $session_id
     * @param string|null $user_id
     * @return boolean
     */
    public function handleLogoutSession(LogInterface $log, string $session_id, string $user_id = null)
    {
        $session = $this->sessionStorage->getSession($session_id);

        if (!$session) {
            return true;
        }

        $loggedInRPs = $this->loggedInRPStorage->getLoggedInRPs($session_id);

        $sid = $session['sid'] ?? null;

        if (!$user_id) {
            $user_id = $session['user_id'];
        }

        if (!$user_id && !$sid) {
            $log::error('Exception while logging out session - there must be a user_id or a sid');
            return false;
        }

        foreach ($loggedInRPs as $loggedInRP) {
            $this->logoutRP($log, $loggedInRP['client_id'], $session_id, $sid, $user_id);
            $this->loggedInRPStorage->removeLoggedInRP($session_id, $loggedInRP['client_id']);
        }

        $this->sessionTokenStorage->removeTokensBySession($session_id);
        $this->sessionTokenStorage->removeSessionTokens($session_id);
        $this->sessionStorage->removeSession($session_id);

        return true;
    }

    /**
     * Handles the logout for a certain rp
     *
     * @param LogInterface $log
     * @param string $clientId
     * @param string $sessionId
     * @return boolean
     */
    public function handleLogoutRP(LogInterface $log, $clientId, $sessionId)
    {
        $session = $this->sessionStorage->getSession($sessionId);

        if(!$session) {
            return false;
        }

        $sid = $session['sid'] ?? null;
        $userId = $session['user_id'];

        if (!$userId && !$sid) {
            $log::error('Exception while logging out session - there must be a user_id or a sid');
            return false;
        }

        $this->sessionTokenStorage->removeTokensBySession($sessionId, $clientId);
        $this->sessionTokenStorage->removeSessionTokens($sessionId, $clientId);

        $result = $this->logoutRP($log, $clientId, $sessionId, $sid, $userId);
        $this->loggedInRPStorage->removeLoggedInRP($sessionId, $clientId);

        return $result;
    }

    /**
     * Saves all related session types by a token
     *
     * @param RequestInterface $request
     * @param string $token
     * @return void
     */
    public function setHandleTokenSession(RequestInterface $request, $token)
    {
        $grantType = $request->request('grant_type') ?? $request->query('grant_type');

        if (!$grantType || !isset($this->grantTypes) || (!($this->grantTypes[$grantType] instanceof AuthorizationCode) && !($this->grantTypes[$grantType] instanceof RefreshToken))) {
            return;
        }

        $sessionId = false;
        $userId = false;
        $clientId = null;
        $code = null;

        if ($this->grantTypes[$grantType] instanceof AuthorizationCode) {
            $code = $this->grantTypes[$grantType]->getAuthCode();      
            $sid = $code['sid'];
            $session = $this->sessionStorage->getSessionBySid($sid);
        }

        if ($this->grantTypes[$grantType] instanceof RefreshToken) {
            $code = $this->grantTypes[$grantType]->getToken();
            $tokenForRefresh = $code['token'];
            $session = $this->sessionTokenStorage->getSessionByToken($tokenForRefresh);
        }

        if (!isset($code['client_id']) || !isset($session['session_id'])) {
            return;
        }

        $clientId = $code['client_id'];
        $sessionId = $session['session_id'];
        $userId = $this->grantTypes[$grantType]->getUserId();

        $this->setSession($sessionId, $userId);

        if (isset($token['refresh_token'])) {
            $this->sessionTokenStorage->setSessionToken($sessionId, $token['refresh_token'], $clientId, true);
        }

        $this->sessionTokenStorage->setSessionToken($sessionId, $token['access_token'], $clientId);
        $this->loggedInRPStorage->setLoggedInRPByToken($sessionId, $token['access_token']);
    }

    /**
     * Validates the logout request
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return boolean
     */
    public function validateRPLogoutRequest(RequestInterface $request, ResponseInterface $response)
    {
        $clientId = null;
        $clientIdTokenHint = null;

        $clientId = $request->request('client_id') ?? $request->query('client_id');
        $idTokenHint = $request->request('id_token_hint') ?? $request->query('id_token_hint');

        if ($idTokenHint) {
            $decodedIdToken = $this->idToken->decodeToken($idTokenHint);
            $clientIdTokenHint = $decodedIdToken['aud'] ?? null;
        }

        if (!$clientIdTokenHint) {
            return false;
        }

        if ($clientId && $clientIdTokenHint && $clientIdTokenHint !== $clientId) {
            $response->setError(400, 'invalid_request', 'The client_id does not match the id_token_hint');
            return false;
        }

        $postLogoutRedirectUri = $request->request('logout_redirect_uri') ?? $request->query('logout_redirect_uri');

        if ($postLogoutRedirectUri && ($clientId || $clientIdTokenHint)) {
            $id = $clientId ?? $clientIdTokenHint;
            $client = $this->clientStorage->getClientDetails($id);
            if ($client && $client['logout_redirect_uri'] !== $postLogoutRedirectUri) {
                $response->setError(400, 'invalid_request', 'The logout_redirect_uri does not match the client ones');
                return false;
            }
        }

        return true;
    }

    /**
     * Set session with generated sid
     *
     * @param string $sessionId
     * @param string $userId
     * @return array
     */
    public function setSession($sessionId, $userId)
    {
        $sid = UniqueToken::uniqueToken();
        $expires = time() + $this->config['session_lifetime'];
        $this->sessionStorage->setSession($sessionId, $userId, $sid, $expires);
        return [
            'session_id' => $sessionId,
            'user_id' => $userId,
            'sid' => $sid,
            'expires' => $expires,
        ];
    }

    /**
     * Logout a certain rp
     *
     * @param LogInterface $log
     * @param string $clientId
     * @param string $sessionId
     * @param string $sid
     * @param string|null $userId
     * @return boolean
     */
    private function logoutRP(LogInterface $log, $clientId, $sessionId, $sid, $userId)
    {
        $client = $this->clientStorage->getClientDetails($clientId);

        if (!$client['backchannel_logout_uri']) {
            return false;
        }

        if (!$client['backchannel_logout_session_required']) {
            $sid = null;
            if (!$userId) {
                $log::error('Exception while logging out session - backchannel logout uri session not required and user id does not exist, but should - for client: ' . $clientId);
                return false;
            }
        }

        $logoutToken = $this->logoutToken->createLogoutToken($clientId, $userId, $sid);

        $data = [
            'headers' => [
                'Accept' => 'application/x-www-form-urlencoded'
            ],
            'form_params' => [
                'logout_token' => $logoutToken
            ]
        ];

        try {
            $response = $this->httpClient->request('POST', $client['backchannel_logout_uri'], $data);
        } catch (\Exception $e) {
            $log::error('Exception caught while logging out session with backchannel logout uri for client: ' . $clientId, [$e]);
            return false;
        }

        if ($response->getStatusCode() !== 200 && $response->getStatusCode() !== 204) {
            $log::error('Unexpected status code while logging out session with backchannel logout uri for client: ' . $clientId, ['statusCode' => $response->getStatusCode(), 'body' => $response->getBody()->getContents()]);
            return false;
        }
        
        return true;
    }

    /**
     * Add grant type
     *
     * @param GrantTypeInterface $grantType  - the grant type to add for the specified identifier
     * @param string|null        $identifier - a string passed in as "grant_type" in the response that will call this grantType
     */
    private function addGrantType(GrantTypeInterface $grantType, $identifier = null)
    {
        if (is_null($identifier) || is_numeric($identifier)) {
            $identifier = $grantType->getQueryStringIdentifier();
        }

        $this->grantTypes[$identifier] = $grantType;
    }
}
