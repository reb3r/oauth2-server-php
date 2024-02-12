<?php
namespace OAuth2\OpenID\Controller;

use GuzzleHttp\Client;
use OAuth2\GrantType\GrantTypeInterface;
use OAuth2\GrantType\RefreshToken;
use OAuth2\LogInterface;
use OAuth2\OpenID\GrantType\AuthorizationCode;
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
        $sid = $session['sid'] ?? null;
        $userId = $session['user_id'];

        if (!$userId && !$sid) {
            $log::error('Exception while logging out session - there must be a user_id or a sid');
            return false;
        }

        $this->sessionTokenStorage->removeTokensBySession($sessionId, $clientId);
        $this->sessionTokenStorage->removeSessionTokens($sessionId, $clientId);

        return $this->logoutRP($log, $clientId, $sessionId, $sid, $userId);
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
        $grantType = $request->request('grant_type');

        $sessionId = false;
        $userId = false;
        $clientId = null;

        if ($this->grantTypes[$grantType] instanceof AuthorizationCode) {
            $authCode = $this->grantTypes[$grantType]->getAuthCode();
            $userId = $this->grantTypes[$grantType]->getUserId();
            $sid = $authCode['sid'] ?? null;
            $session = $this->sessionStorage->getSessionBySid($sid);
            $sessionId = $session['session_id'] ?? null;
            $clientId = $authCode['client_id'] ?? null;
        }

        if ($this->grantTypes[$grantType] instanceof RefreshToken) {
            $resfreshToken = $this->grantTypes[$grantType]->getToken();
            $userId = $this->grantTypes[$grantType]->getUserId();
            $token = $resfreshToken['token'] ?? null;
            $sessionToken = $this->sessionTokenStorage->getSessionByToken($token);
            $sessionId = $sessionToken['session_id'] ?? null;
            $clientId = $resfreshToken['client_id'] ?? null;
        }

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

        if ($request->request('client_id')) {
            $clientId = $request->request('client_id');
        }

        if ($request->query('client_id')) {
            $clientId = $request->query('client_id');
        }

        if ($request->request('id_token_hint')) {
            $decodedIdToken = $this->idToken->decodeToken($request->request('id_token_hint'));
            $clientIdTokenHint = $decodedIdToken['aud'] ?? null;
        }

        if ($request->query('id_token_hint')) {
            $decodedIdToken = $this->idToken->decodeToken($request->query('id_token_hint'));
            $clientIdTokenHint = $decodedIdToken['aud'] ?? null;
        }

        if (($request->request('client_id') && $request->request('id_token_hint')) || ($request->query('client_id') && $request->query('id_token_hint'))) {
            if ($clientIdTokenHint !== $clientId) {
                $response->setError(400, 'invalid_request', 'The client_id does not match the id_token_hint');
                return false;
            }
        }

        if (!$clientId && !$clientIdTokenHint) {
            return false;
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
        if ($session = $this->sessionStorage->getSession($sessionId)) {
            return $session;
        }
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
     * @param string $userId
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
                $log::error('Exception while logging out session - backchannel logout uri not required but no user id existing for client: ' . $clientId);
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
        
        $this->loggedInRPStorage->removeLoggedInRP($sessionId, $clientId);
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
