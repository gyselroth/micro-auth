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

class OidcAzure extends AbstractAdapter
{
    /**
     * Tenant.
     *
     * @var string
     */
    protected $tenant = 'common';

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
     * @param iterable $config
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

        return parent::setOptions($config);
    }

    /**
     * Authenticate.
     */
    public function authenticate(ServerRequestInterface $request): ?array
    {
        $header = $request->getHeader('Authorization');

        if (0 === count($header)) {
            $this->logger->debug('skip auth adapter ['.get_class($this).'], no http authorization header found', [
                'category' => get_class($this),
            ]);

            return null;
        }

        $parts = explode(' ', $header[0]);
        $tks = explode('.', $parts[1]);

        if ('Bearer' === $parts[0] && 3 == count($tks) && !empty($tks[2])) {
            $this->logger->debug('found http bearer jwt token in authorization header', [
                'category' => get_class($this),
            ]);

            return $this->verifyToken($parts[1]);
        }

        $this->logger->debug('http authorization header contains no jwt bearer string or invalid authentication string', [
            'category' => get_class($this),
        ]);

        return null;
    }

    /**
     * Get attributes.
     */
    public function getAttributes(IdentityInterface $identity): array
    {
        return $this->attributes;
    }

    /**
     * Token verification.
     */
    protected function verifyToken(string $token): ?array
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

        return $claims;
    }
}
