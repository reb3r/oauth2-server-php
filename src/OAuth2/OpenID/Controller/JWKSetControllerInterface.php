<?php
namespace OAuth2\OpenID\Controller;

use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

interface JWKSetControllerInterface
{

    /**
     * Handle the JWK endpoint request
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @param
     *            $is_authorized
     * @param null $user_id
     * @return mixed
     */
    public function handleJWKSetRequest(RequestInterface $request, ResponseInterface $response);

    /**
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return bool
     */
    public function validateJWKSetRequest(RequestInterface $request, ResponseInterface $response);
}

