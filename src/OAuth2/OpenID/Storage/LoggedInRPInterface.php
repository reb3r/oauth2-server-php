<?php

namespace OAuth2\OpenID\Storage;

/**
 * Implement this interface to specify where the OAuth2 Server
 * should store logged in rps.
 * This is neccessary for backchannel logout.
 * https://openid.net/specs/openid-connect-backchannel-1_0.html
 */
interface LoggedInRPInterface
{
    /**
     * Save the client and session for the logged in user by access token
     * This function is a helper, if we don't have the client id
     *
     * @param string $session_id    - user session id
     * @param string $token         - access token
     * @return boolean
     */
    public function setLoggedInRPByToken($session_id, $token);
    
    /**
     * Get all logged in clients of a user by a specific session
     *
     * @param string $session_id    - user session id
     * @return array
     */
    public function getLoggedInRPs($session_id);

    /**
     * Remove logged in client according to session
     *
     * @param string $session_id    - user session id
     * @param string $client_id     - the client id
     * @return boolean
     */
    public function removeLoggedInRP($session_id, $client_id);
}