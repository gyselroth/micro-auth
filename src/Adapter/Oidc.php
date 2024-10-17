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
use Micro\Auth\IdentityInterface;
use Psr\Http\Message\ServerRequestInterface;
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
     * Token validation endpoint (rfc7662).
     *
     * @var string
     */
    protected $token_validation_url;

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
     * @param iterable $config
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

        return parent::setOptions($config);
    }

    /**
     * Authenticate.
     */
    public function authenticate(ServerRequestInterface $request): ?array
    {
        $header = $request->getHeader('Authorization');

        if (0 === count($header)) {
            $this->logger->debug('skip auth adapter ['.get_class($this).'], no http authorization header or access_token param found', [
                'category' => get_class($this),
            ]);

            return null;
        }

        $parts = explode(' ', $header[0]);

        if ('Bearer' === $parts[0]) {
            $this->logger->debug('found http bearer authorization header', [
                'category' => get_class($this),
            ]);

            return $this->verifyToken($parts[1]);
        }

        $this->logger->debug('http authorization header contains no bearer string or invalid authentication string', [
            'category' => get_class($this),
        ]);

        return null;
    }

    /**
     * Get discovery url.
     */
    public function getDiscoveryUrl(): string
    {
        return $this->provider_url.self::DISCOVERY_PATH;
    }

    /**
     * Get discovery document.
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
     */
    public function getAttributes(IdentityInterface $identity): array
    {
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

            return $attributes;
        }
        $this->logger->error('failed requesting user attributes from userinfo_endpoint, status code ['.$code.']', [
            'category' => get_class($this),
        ]);

        throw new OidcException\UserInfoRequestFailed('failed requesting user attribute from userinfo_endpoint');
    }

    /**
     * Token verification.
     */
    protected function verifyToken(string $token): ?array
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

            $this->access_token = $token;

            return $claims;
        } else {
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
        $attributes = json_decode($result, true);

        if (200 === $code) {
            $this->logger->debug('successfully verified oauth2 access token via authorization server', [
                'category' => get_class($this),
            ]);
            $this->access_token = $token;

            return $attributes;
        }

        $this->logger->error('failed verify oauth2 access token via authorization server, received status ['.$code.']', [
            'category' => get_class($this),
        ]);

        throw new OidcException\InvalidAccessToken('failed verify oauth2 access token via authorization server');
    }
}
