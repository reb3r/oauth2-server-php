<?php
namespace OAuth2\OpenID\Controller;

use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

interface DiscoveryControllerInterface
{

    /**
     * Handle the OP configuration request
     * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @param
     *            $is_authorized
     * @param null $user_id
     * @return mixed
     */
    public function handleConfigurationDiscoveryRequest(RequestInterface $request, ResponseInterface $response);

    /**
     * Validates the OP configuration request
     * Must be an GET-Request. Must contain /.well-known/openid-configuration in URI
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return bool
     */
    public function validateConfigurationDiscoveryRequest(RequestInterface $request, ResponseInterface $response);
}
