<?php
namespace OAuth2\OpenID\Controller;

use OAuth2\LogInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

interface LogoutControllerInterface
{
    /**
     * Handle the complete session logout
     *
     * @param LogInterface $log
     * @param string $session_id
     * @param string|null $user_id
     * @return boolean
     */
    public function handleLogoutSession(LogInterface $log, string $session_id, string $user_id = null);

    /**
     * Handles the logout for a certain rp
     *
     * @param LogInterface $log
     * @param string $clientId
     * @param string $sessionId
     * @return boolean
     */
    public function handleLogoutRP(LogInterface $log, $clientId, $sessionId);

    /**
     * Saves all related session types by a token
     *
     * @param RequestInterface $request
     * @param string $token
     * @return void
     */
    public function setHandleTokenSession(RequestInterface $request, $token);

    /**
     * Validates the logout request
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return boolean
     */
    public function validateRPLogoutRequest(RequestInterface $request, ResponseInterface $response);

    /**
     * Updates or sets session with generated sid and updated expires timestamp
     *
     * @param string $sessionId
     * @param string $userId
     * @return array
     */
    public function updateOrSetSession($sessionId, $userId);
}
