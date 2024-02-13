<?php

namespace OAuth2\OpenID\Storage;

/**
 * Implement this interface to specify where the OAuth2 Server
 * should store relations between session and tokens.
 * This is neccessary for backchannel logout.
 * https://openid.net/specs/openid-connect-backchannel-1_0.html
 */
interface SessionTokenInterface
{
    /**
     * Sets relation between session and token
     *
     * @param string $session_id            - user session id
     * @param string $token                 - access or refresh token
     * @param string $client_id             - the client id
     * @param boolean $is_refresh_token     - OPTIONAL if token is refresh token, so we can find it later
     * @return boolean
     */
    public function setSessionToken($session_id, $token, $client_id, bool $is_refresh_token = false);
    
    /**
     * Returns data of relations table between tokens and session
     *
     * @param string $session_id    - user session id
     * @param string $client_id     - OPTIONAL the client id
     * @return array
     */
    public function getSessionTokens($session_id, $client_id = null);

    /**
     * Remvoes the relation between token and session
     *
     * @param string $session_id    - user session id
     * @param string $client_id     - OPTIONAL the client id
     * @return boolean
     */
    public function removeSessionTokens($session_id, $client_id = null);

    /**
     * Returns all access and refresh tokens for a certain session
     *
     * @param string $session_id    - user session id
     * @param string $client_id     - the client id
     * @return array
     */
    public function getTokensBySession($session_id, $client_id = null);

    /**
     * Returns the session token relation by a token
     *
     * @param string $token
     * @return array|boolean
     */
    public function getSessionByToken($token);
    
    /**
     * Removes all access and refresh tokens if there is a relation between session and token
     * Only refresh tokens they dont have the scope 'offline_access'
     *
     * @param string $session_id    - user session id
     * @param string $client_id     - the client id
     * @return boolean
     */
    public function removeTokensBySession($session_id, $client_id = null);
}