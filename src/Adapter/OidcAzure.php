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

class OidcAzure extends AbstractAdapter
{
    /**
     * Tenant.
     *
     * @var string
     */
    protected $tenant = '';

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
     * Identity Attribute
     *
     * @var string
     */
    protected $identity_attribute = 'preferred_username';

    /**
     * LoggerInterface.
     *
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * Init adapter.
     *
     * @param LoggerInterface $logger
     * @param iterable        $config
     */
    public function __construct(LoggerInterface $logger, ?Iterable $config = null)
    {
        $this->logger = $logger;
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
                case 'tenant':
                case 'client_id':
                case 'default_end_point_version':
                case 'identity_attribute':
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
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $parts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            $tks = explode('.', $parts[1]);

            if ('Bearer' === $parts[0] && 3 == count($tks) && !empty($tks[2])) {
                $this->logger->debug('found http bearer jwt token in authorization header', [
                    'category' => get_class($this),
                ]);

                return $this->verifyToken($parts[1]);
            }
            $this->logger->debug('no bearer jwt token provided', [
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
     * Get attributes.
     *
     * @return array
     */
    public function getAttributes(): array
    {
        return $this->attributes;
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
        $this->logger->debug('validate jwt token', [
            'category' => get_class($this),
        ]);

        try {
            $claims = (new \TheNetworg\OAuth2\Client\Provider\Azure([
                'tenant' => $this->tenant,
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

        return true;
    }
}
