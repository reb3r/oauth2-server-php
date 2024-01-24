<?php
namespace OAuth2\OpenID\Controller;

use GuzzleHttp\Client;
use OAuth2\LogInterface;
use OAuth2\OpenID\RequestType\LogoutTokenInterface;
use OAuth2\OpenID\Storage\LoggedInRPInterface;
use OAuth2\OpenID\Storage\SessionInterface;
use OAuth2\OpenID\Storage\SessionTokenInterface;
use OAuth2\Storage\ClientInterface;

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

    public function __construct(SessionInterface $sessionStorage, LoggedInRPInterface $loggedInRPStorage, ClientInterface $clientStorage, SessionTokenInterface $sessionTokenStorage, LogoutTokenInterface $logoutToken)
    {
        $this->sessionStorage = $sessionStorage;
        $this->loggedInRPStorage = $loggedInRPStorage;
        $this->clientStorage = $clientStorage;
        $this->sessionTokenStorage = $sessionTokenStorage;
        $this->logoutToken = $logoutToken;
    }

    /**
     * Handle the session logout for backchannel logout
     *
     * @param LogInterface $log
     * @param Client $client
     * @param string $session_id
     * @param string|null $user_id
     * @return boolean
     */
    public function logoutSession(LogInterface $log, Client $client, string $session_id, string $user_id = null)
    {
        $session = $this->sessionStorage->getSession($session_id);
        $loggedInRPs = $this->loggedInRPStorage->getLoggedInRPs($session_id);

        $httpClient = $client;

        $sid = $session['sid'] ?? null;

        if (!$user_id) {
            $user_id = $session['user_id'];
        }

        if (!$user_id && !$sid) {
            $log::error('Exception while logging out session - there must be a user_id or a sid');
            return false;
        }

        foreach ($loggedInRPs as $loggedInRP) {
            $client = $this->clientStorage->getClientDetails($loggedInRP['client_id']);

            if (!$client['backchannel_logout_uri']) {
                continue;
            }

            if ($client['backchannel_logout_session_required']) {
                $user_id = null;
                if (!$sid) {
                    $log::error('Exception while logging out session - backchannel logout uri required but not set for client: ' . $loggedInRP['client_id']);
                    continue;
                }
            } else {
                $sid = null;
                if (!$user_id) {
                    $log::error('Exception while logging out session - backchannel logout uri not required but no user id existing for client: ' . $loggedInRP['client_id']);
                    continue;
                }
            }

            $logoutToken = $this->logoutToken->createLogoutToken($loggedInRP['client_id'], $user_id, $sid);

            $data = [
                'headers' => [
                    'Accept' => 'application/x-www-form-urlencoded'
                ],
                'form_params' => [
                    'logout_token' => $logoutToken
                ]
            ];

            try {
                $response = $httpClient->request('POST', $client['backchannel_logout_uri'], $data);
            } catch (\Exception $e) {
                $log::error('Exception caught while logging out session with backchannel logout uri for client: ' . $loggedInRP['client_id'], [$e]);
                continue;
            }

            if ($response->getStatusCode() !== 200 && $response->getStatusCode() !== 204) {
                $log::error('Unexpected status code while logging out session with backchannel logout uri for client: ' . $loggedInRP['client_id'], ['statusCode' => $response->getStatusCode(), 'body' => $response->getBody()->getContents()]);
                continue;
            }
            
            $this->loggedInRPStorage->removeLoggedInRP($session_id, $loggedInRP['client_id']);
        }

        $this->sessionTokenStorage->removeTokensBySession($session_id);
        $this->sessionTokenStorage->removeSessionTokens($session_id);
        $this->sessionStorage->removeSession($session_id);

        return true;
    }
}
