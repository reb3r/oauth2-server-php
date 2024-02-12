<?php

namespace OAuth2\OpenID\Storage;

/**
 * Implement this interface to specify where the OAuth2 Server
 * should store user sessions.
 * This is neccessary for backchannel logout.
 * https://openid.net/specs/openid-connect-backchannel-1_0.html
 */
interface SessionInterface
{
    /**
     * Save the session of a user
     *
     * @param string $session_id    - user session id
     * @param string $user_id       - user id
     * @param string $sid           - sid (session ID) for clients
     * @param int $expires          - expiration to be stored as a Unix timestamp.
     * @return boolean
     */
    public function setSession($session_id, $user_id, $sid, $expires);
    
    /**
     * Get the session by id
     *
     * @param string $session_id    - user session id
     * @return array|boolean
     */
    public function getSession($session_id);

    /**
     * Get the session by sid
     *
     * @param string $sid
     * @return array|boolean
     */
    public function getSessionBySid($sid);

    /**
     * Remove the stored session
     *
     * @param string $session_id    - user session id
     * @return boolean
     */
    public function removeSession($session_id);
}