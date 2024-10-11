<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @copyright   Copryright (c) 2015-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth\Adapter;

use Micro\Auth\Adapter\Oidc\Exception as OidcException;
use Micro\Auth\Exception;
use Psr\Log\LoggerInterface;

class Oidc extends AbstractAdapter
{
    /**
     * OpenID-connect discovery path.
     */
    const DISCOVERY_PATH = '/.well-known/openid-configuration';

    /**
     * OpenID-connect provider url.
     *
     * @var string
     */
    protected $provider_url = 'https://oidc.example.org';

    /**
     * Token validation endpoint (rfc7662).
     *
     * @var string
     */
    protected $token_validation_url;

    /**
     * ClientId.
     *
     * @var string
     */
    protected $client_id = '';

    /**
     * Default endpoint version.
     *
     * @var string
     */
    protected $default_end_point_version = '2.0';

    /**
     * Attributes.
     *
     * @var array
     */
    protected $attributes = [];

    /**
     * LoggerInterface.
     *
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * Access token.
     *
     * @var string
     */
    private $access_token;

    /**
     * Init adapter.
     *
     * @param LoggerInterface $logger
     * @param iterable        $config
     */
    public function __construct(LoggerInterface $logger, ?Iterable $config = null)
    {
        $this->logger = $logger;
        $this->identity_attribute = 'preferred_username';
        $this->setOptions($config);
    }

    /**
     * Set options.
     *
     * @param iterable $config
     *
     * @return AdapterInterface
     */
    public function setOptions(? Iterable $config = null): AdapterInterface
    {
        if (null === $config) {
            return $this;
        }

        foreach ($config as $option => $value) {
            switch ($option) {
                case 'provider_url':
                case 'token_validation_url':
                case 'client_id':
                case 'default_end_point_version':
                    $this->{$option} = (string) $value;
                    unset($config[$option]);

                    break;
            }
        }

        return  parent::setOptions($config);
    }

    /**
     * Authenticate.
     *
     * @return bool
     */
    public function authenticate(): bool
    {
        if (isset($_GET['access_token'])) {
            $this->logger->warning('found access_token in query string, you should use a bearer token instead due security reasons https://tools.ietf.org/html/rfc6750#section-2.3', [
                'category' => get_class($this),
            ]);

            return $this->verifyToken($_GET['access_token']);
        }
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $header = $_SERVER['HTTP_AUTHORIZATION'];
            $parts = explode(' ', $header);

            if ('Bearer' === $parts[0]) {
                $this->logger->debug('found http bearer authorization header', [
                    'category' => get_class($this),
                ]);

                return $this->verifyToken($parts[1]);
            }
            $this->logger->debug('no bearer token provided', [
                'category' => get_class($this),
            ]);

            return false;
        }

        $this->logger->debug('http authorization header contains no bearer string or invalid authentication string', [
            'category' => get_class($this),
        ]);

        return false;
    }

    /**
     * Get discovery url.
     *
     * @return string
     */
    public function getDiscoveryUrl(): string
    {
        return $this->provider_url.self::DISCOVERY_PATH;
    }

    /**
     * Get discovery document.
     *
     * @return array
     */
    public function getDiscoveryDocument(): array
    {
        if ($apc = extension_loaded('apc') && apc_exists($this->provider_url)) {
            return apc_get($this->provider_url);
        }
        $ch = curl_init();
        $url = $this->getDiscoveryUrl();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        $this->logger->debug('fetch openid-connect discovery document from ['.$url.']', [
            'category' => get_class($this),
        ]);

        $result = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if (200 === $code) {
            $discovery = json_decode($result, true);
            $this->logger->debug('received openid-connect discovery document from ['.$url.']', [
                'category' => get_class($this),
                'discovery' => $discovery,
            ]);

            if (true === $apc) {
                apc_store($this->provider_url, $discovery);
            }

            return $discovery;
        }
        $this->logger->error('failed to receive openid-connect discovery document from ['.$url.'], request ended with status ['.$code.']', [
            'category' => get_class($this),
        ]);

        throw new OidcException\DiscoveryNotFound('failed to get openid-connect discovery document');
    }

    /**
     * Get attributes.
     *
     * @return array
     */
    public function getAttributes(): array
    {
        if (0 !== count($this->attributes)) {
            return $this->attributes;
        }

        $discovery = $this->getDiscoveryDocument();
        if (!(isset($discovery['authorization_endpoint']))) {
            throw new OidcException\AuthorizationEndpointNotSet('authorization_endpoint could not be determained');
        }

        $this->logger->debug('fetch user attributes from userinfo_endpoint ['.$discovery['userinfo_endpoint'].']', [
            'category' => get_class($this),
        ]);

        $url = $discovery['userinfo_endpoint'].'?access_token='.$this->access_token;
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $result = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        $response = json_decode($result, true);

        if (200 === $code) {
            $attributes = json_decode($result, true);
            $this->logger->debug('successfully requested user attributes from userinfo_endpoint', [
                'category' => get_class($this),
            ]);

            return $this->attributes = $attributes;
        }
        $this->logger->error('failed requesting user attributes from userinfo_endpoint, status code ['.$code.']', [
            'category' => get_class($this),
        ]);

        throw new OidcException\UserInfoRequestFailed('failed requesting user attribute from userinfo_endpoint');
    }

    /**
     * Token verification.
     *
     * @param string $token
     *
     * @return bool
     */
    protected function verifyToken(string $token): bool
    {
        $tks = explode('.', $token);

        if ($this->token_validation_url) {
            $this->logger->debug('validate oauth2 token via rfc7662 token validation endpoint ['.$this->token_validation_url.']', [
                'category' => get_class($this),
            ]);

            $url = str_replace('{token}', $token, $this->token_validation_url);
        } elseif (3 == count($tks) && !empty($tks[2])) {
            $this->logger->debug('validate jwt token', [
                'category' => get_class($this),
            ]);

            try {
                $claims = (new \TheNetworg\OAuth2\Client\Provider\Azure([
                    'clientId' => $this->client_id,
                    'defaultEndPointVersion' => $this->default_end_point_version
                ]))->validateAccessToken($token);
            } catch (\Exception $exception) {
                $this->logger->error('cannot get claims of accessToken', [
                    'category' => get_class($this),
                    'exception' => $exception
                ]);

                throw new OidcException\InvalidAccessToken('failed to verify jwt token via authorization server');
            }

            if (!isset($claims[$this->identity_attribute])) {
                throw new Exception\IdentityAttributeNotFound('identity attribute '.$this->identity_attribute.' not found in response');
            }

            $this->identifier = $claims[$this->identity_attribute];
            $this->attributes = $claims;
            $this->access_token = $token;

            return true;
        }
        else {
            $discovery = $this->getDiscoveryDocument();
            if (!(isset($discovery['userinfo_endpoint']))) {
                throw new OidcException\UserEndpointNotSet('userinfo_endpoint could not be determained');
            }

            $this->logger->debug('validate token via openid-connect userinfo_endpoint ['.$discovery['userinfo_endpoint'].']', [
                'category' => get_class($this),
            ]);

            $url = $discovery['userinfo_endpoint'].'?access_token='.$token;
        }

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $result = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        $response = json_decode($result, true);

        if (200 === $code) {
            $attributes = json_decode($result, true);
            $this->logger->debug('successfully verified oauth2 access token via authorization server', [
                'category' => get_class($this),
            ]);

            if (!isset($attributes[$this->identity_attribute])) {
                throw new Exception\IdentityAttributeNotFound('identity attribute '.$this->identity_attribute.' not found in oauth2 response');
            }

            $this->identifier = $attributes[$this->identity_attribute];

            if ($this->token_validation_url) {
                $this->attributes = $attributes;
            } else {
                $this->access_token = $token;
            }

            return true;
        }
        $this->logger->error('failed verify oauth2 access token via authorization server, received status ['.$code.']', [
            'category' => get_class($this),
        ]);

        throw new OidcException\InvalidAccessToken('failed verify oauth2 access token via authorization server');
    }
}
