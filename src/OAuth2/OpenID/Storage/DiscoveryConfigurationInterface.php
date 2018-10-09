<?php
namespace OAuth2\OpenID\Storage;

/**
 * Implement this interface to specify where the OpenID Connect Server
 * should get configuration for OpenID Configuration Request
 * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
 *
 * @author Christian Reber <christian at reb3r dot de>
 */
interface DiscoveryConfigurationInterface
{

    /**
     * Get configuration for OpenID Discovery
     * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
     *
     * @return mixed
     */
    public function getDiscoveryConfiguration();
}
