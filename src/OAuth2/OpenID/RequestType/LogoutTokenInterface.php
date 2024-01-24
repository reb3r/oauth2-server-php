<?php

namespace OAuth2\OpenID\RequestType;

interface LogoutTokenInterface extends RequestTypeInterface
{
    /**
     * Create Logout Token
     * 
     * If Backchannel Logout should be used this token needs to be send to the clients
     * 
     * 
     * @param mixed $client_id      - The client id
     * @param mixed $user_id        - OPTIONAL user id
     * @param string $sid           - OPTIONAL session id
     * 
     * @return string The Logout Token represented as a JSON Web Token (JWT).
     * 
     * @see https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
     */
    public function createLogoutToken($client_id, $user_id = null, $sid = null);
}
