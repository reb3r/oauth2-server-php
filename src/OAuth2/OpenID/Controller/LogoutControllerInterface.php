<?php
namespace OAuth2\OpenID\Controller;

use GuzzleHttp\Client;
use OAuth2\LogInterface;

interface LogoutControllerInterface
{
    /**
     * Handle the logout process for backchannel logout
     *
     * @param LogInterface $log
     * @param Client $client
     * @param string $session_id
     * @param string|null $user_id
     * @return boolean
     */
    public function logoutSession(LogInterface $log, Client $client, string $session_id, string $user_id = null);
}
