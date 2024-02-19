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
     * Saves the logged in rps
     *
     * @param string $session_id
     * @param string $client_id
     * @return boolean
     */
    public function setLoggedInRP($session_id, $client_id);

    /**
     * Get all logged in clients of a user by a specific session
     *
     * @param string $session_id    - user session id
     * @return array
     */
    public function getLoggedInRPs($session_id);

    /**
     * Gets a specific logged in client of a user
     *
     * @param string $session_id
     * @param string $client_id
     * @return array|boolean
     */
    public function getLoggedInRPForSession($session_id, $client_id);

    /**
     * Remove logged in client according to session
     *
     * @param string $session_id    - user session id
     * @param string $client_id     - the client id
     * @return boolean
     */
    public function removeLoggedInRP($session_id, $client_id);
}