<?php
namespace OAuth2\OpenID\Controller;

use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\OpenID\Storage\DiscoveryConfigurationInterface;

class DiscoveryController implements DiscoveryControllerInterface
{
    protected $configurationStorage;

    public function __construct(DiscoveryConfigurationInterface $configurationStorage)
    {
        $this->configurationStorage = $configurationStorage;
    }

    /**
     * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
     *
     * {@inheritdoc}
     * @see \OAuth2\OpenID\Controller\DiscoveryControllerInterface::handleConfigurationDiscoveryRequest()
     */
    public function handleConfigurationDiscoveryRequest(RequestInterface $request, ResponseInterface $response)
    {
        $configuration = $this->configurationStorage->getDiscoveryConfiguration();

        $response->setStatusCode(200);
        $response->addParameters(array_filter($configuration)); // Remove empty values
        $response->addHttpHeaders(array(
            'Content-Type' => 'application/json'
        ));
    }

    /**
     *
     * {@inheritdoc}
     * @see \OAuth2\OpenID\Controller\DiscoveryControllerInterface::validateConfigurationDiscoveryRequest()
     */
    public function validateConfigurationDiscoveryRequest(RequestInterface $request, ResponseInterface $response)
    {
        // TODO: Validation required: Must be an GET-Request. Must contain /.well-known/openid-configuration in URI
        return true;
    }
}
