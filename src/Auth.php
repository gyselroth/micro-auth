<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @copyright   Copryright (c) 2015-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth;

use InvalidArgumentException;
use Micro\Auth\Adapter\AdapterInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

class Auth
{
    /**
     * Adapter.
     *
     * @var array
     */
    protected $adapter = [];

    /**
     * Logger.
     *
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * Identity class.
     *
     * @var string
     */
    protected $identity_class = Identity::class;

    /**
     * Attribute map class.
     *
     * @var string
     */
    protected $attribute_map_class = AttributeMap::class;

    /**
     * Initialize.
     *
     * @param iterable $config
     */
    public function __construct(LoggerInterface $logger, ?array $config = null)
    {
        $this->logger = $logger;
        $this->setOptions($config);
    }

    /**
     * Set options.
     */
    public function setOptions(?array $config = null): self
    {
        if (null === $config) {
            return $this;
        }

        foreach ($config as $option => $value) {
            switch ($option) {
                case 'identity_class':
                case 'attribute_map_class':
                    $this->{$option} = (string) $value;

                    break;
                default:
                    throw new InvalidArgumentException('invalid option '.$option.' given');
            }
        }

        return $this;
    }

    /**
     * Check if adapter is injected.
     */
    public function hasAdapter(string $name): bool
    {
        return isset($this->adapter[$name]);
    }

    /**
     * Inject auth adapter.
     */
    public function injectAdapter(AdapterInterface $adapter, ?string $name = null): self
    {
        if (null === $name) {
            $name = get_class($adapter);
        }

        $this->logger->debug('inject auth adapter ['.$name.'] of type ['.get_class($adapter).']', [
            'category' => get_class($this),
        ]);

        if ($this->hasAdapter($name)) {
            throw new Exception\AdapterNotUnique('auth adapter '.$name.' is already registered');
        }

        $this->adapter[$name] = $adapter;

        return $this;
    }

    /**
     * Get adapter.
     */
    public function getAdapter(string $name): AdapterInterface
    {
        if (!$this->hasAdapter($name)) {
            throw new Exception\AdapterNotFound('auth adapter '.$name.' is not registered');
        }

        return $this->adapter[$name];
    }

    /**
     * Get adapters.
     */
    public function getAdapters(array $adapters = []): array
    {
        if (empty($adapter)) {
            return $this->adapter;
        }
        $list = [];
        foreach ($adapter as $name) {
            if (!$this->hasAdapter($name)) {
                throw new Exception\AdapterNotFound('auth adapter '.$name.' is not registered');
            }
            $list[$name] = $this->adapter[$name];
        }

        return $list;
    }

    /**
     * Authenticate.
     */
    public function requireOne(ServerRequestInterface $request): ?IdentityInterface
    {
        foreach ($this->adapter as $name => $adapter) {
            try {
                if ($attributes = $adapter->authenticate($request)) {
                    $id = $this->createIdentity($adapter, $attributes);

                    $this->logger->info("identity [{$id->getIdentifier()}] authenticated over adapter [{$name}]", [
                        'category' => get_class($this),
                    ]);

                    return $id;
                }
            } catch (\Exception $e) {
                $this->logger->error('failed authenticate user, unexcepted exception was thrown', [
                    'category' => get_class($this),
                    'exception' => $e,
                ]);
            }

            $this->logger->debug("auth adapter [{$name}] failed", [
                'category' => get_class($this),
            ]);
        }

        throw new Exception\NotAuthenticated('all authentication adapter have failed');
    }

    /**
     * Create identity.
     */
    protected function createIdentity(AdapterInterface $adapter, array $attributes): IdentityInterface
    {
        if (!isset($attributes[$adapter->getIdentityAttribute()])) {
            throw new Exception\IdentityAttributeNotFound('identity attribute not found');
        }

        $identity = $attributes[$adapter->getIdentityAttribute()];
        if (is_array($identity)) {
            $identity = (string) array_shift($identity);
        }

        $map = new $this->attribute_map_class($adapter->getAttributeMap(), $this->logger);

        return new $this->identity_class($adapter, $identity, $map);
    }
}
