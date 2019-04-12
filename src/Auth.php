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
     * Identity.
     *
     * @var IdentityInterface
     */
    protected $identity;

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
     * @param LoggerInterface $logger
     * @param iterable        $config
     */
    public function __construct(LoggerInterface $logger, ? Iterable $config = null)
    {
        $this->logger = $logger;
        $this->setOptions($config);
    }

    /**
     * Set options.
     *
     * @param iterable $config
     *
     * @return Auth
     */
    public function setOptions(? Iterable $config = null): self
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
     *
     * @param string $name
     *
     * @return bool
     */
    public function hasAdapter(string $name): bool
    {
        return isset($this->adapter[$name]);
    }

    /**
     * Inject auth adapter.
     *
     * @param AdapterInterface $adapter
     * @param string           $name
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
     *
     * @param string $name
     *
     * @return AdapterInterface
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
     *
     * @return AdapterInterface[]
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
     *
     * @return bool
     */
    public function requireOne(): bool
    {
        $result = false;

        foreach ($this->adapter as $name => $adapter) {
            $adapter->setup();

            try {
                if ($adapter->authenticate()) {
                    $this->createIdentity($adapter);

                    $this->logger->info("identity [{$this->identity->getIdentifier()}] authenticated over adapter [{$name}]", [
                        'category' => get_class($this),
                    ]);
                    $_SERVER['REMOTE_USER'] = $this->identity->getIdentifier();

                    return true;
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

        $this->logger->warning('all authentication adapter have failed', [
            'category' => get_class($this),
        ]);

        return false;
    }

    /**
     * Get identity.
     *
     * @return IdentityInterface
     */
    public function getIdentity(): IdentityInterface
    {
        if (!$this->isAuthenticated()) {
            throw new Exception\NotAuthenticated('no valid authentication yet');
        }

        return $this->identity;
    }

    /**
     * Check if valid identity exists.
     *
     * @return bool
     */
    public function isAuthenticated(): bool
    {
        return $this->identity instanceof Identity;
    }

    /**
     * Create identity.
     *
     * @param AdapterInterface $adapter
     *
     * @return IdentityInterface
     */
    public function createIdentity(AdapterInterface $adapter): IdentityInterface
    {
        $map = new $this->attribute_map_class($adapter->getAttributeMap(), $this->logger);
        $this->identity = new $this->identity_class($adapter, $map, $this->logger);

        return $this->identity;
    }
}
