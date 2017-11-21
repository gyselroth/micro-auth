<?php
declare(strict_types = 1);

/**
 * Micro
 *
 * @author    Raffael Sahli <sahli@gyselroth.net>
 * @copyright Copyright (c) 2017 gyselroth GmbH (https://gyselroth.com)
 * @license   MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth;

use \Micro\Auth\Exception;
use \Micro\Auth\Adapter\AdapterInterface;
use \Micro\Auth\Identity;
use \Psr\Log\LoggerInterface;
use \Micro\Auth\AttributeMap;
use \Micro\Container\AdapterAwareInterface;

class Auth implements AdapterAwareInterface
{
    /**
     * Adapter
     *
     * @var array
     */
    protected $adapter = [];


    /**
     * Identity
     *
     * @var Identity
     */
    protected $identity;


    /**
     * Logger
     *
     * @var LoggerInterface
     */
    protected $logger;


    /**
     * Identity class
     *
     * @var string
     */
    protected $identity_class = Identity::class;


    /**
     * Attribute map class
     *
     * @var string
     */
    protected $attribute_map_class = AttributeMap::class;


    /**
     * Initialize
     *
     * @param   LoggerInterface $logger
     * @param   Iterable $config
     * @return  void
     */
    public function __construct(LoggerInterface $logger, ? Iterable $config = null)
    {
        $this->logger = $logger;
        $this->setOptions($config);
    }


    /**
     * Set options
     *
     * @param  Iterable $config
     * @return Auth
     */
    public function setOptions(? Iterable $config = null) : Auth
    {
        if ($config === null) {
            return $this;
        }

        foreach ($config as $option => $value) {
            switch ($option) {
                case 'identity_class':
                case 'attribute_map_class':
                    $this->{$option} = (string)$value;
                break;
                case 'adapter':
                    foreach($value as $name => $adapter) {
                        $this->injectAdapter($name, $adapter);
                    }
                break;
                default:
                    throw new Exception('invalid option '.$option.' given');
            }
        }

        return $this;
    }


    /**
     * {@inheritDoc}
     */
    public function hasAdapter(string $name): bool
    {
        return isset($this->adapter[$name]);
    }


    /**
     * {@inheritDoc}
     */
    public function getDefaultAdapter(): array
    {
        return [];
    }


    /**
     * {@inheritDoc}
     */
    public function injectAdapter($adapter, ?string $name=null) : AdapterAwareInterface
    {
        if(!($adapter instanceof AdapterInterface)) {
            throw new Exception('adapter needs to implement AdapterInterface');
        }

        if($name === null) {
            $name = get_class($adapter);
        }

        $this->logger->debug('inject auth adapter ['.$name.'] of type ['.get_class($adapter).']', [
            'category' => get_class($this)
        ]);

        if ($this->hasAdapter($name)) {
            throw new Exception('auth adapter '.$name.' is already registered');
        }

        $this->adapter[$name] = $adapter;
        return $this;
    }


    /**
     * {@inheritDoc}
     */
    public function getAdapter(string $name)
    {
        if (!$this->hasAdapter($name)) {
            throw new Exception('auth adapter '.$name.' is not registered');
        }

        return $this->adapter[$name];
    }


    /**
     * {@inheritDoc}
     */
    public function getAdapters(array $adapters = []): array
    {
        if (empty($adapter)) {
            return $this->adapter;
        } else {
            $list = [];
            foreach ($adapter as $name) {
                if (!$this->hasAdapter($name)) {
                    throw new Exception('auth adapter '.$name.' is not registered');
                }
                $list[$name] = $this->adapter[$name];
            }

            return $list;
        }
    }


    /**
     * Create identity
     *
     * @param  AdapterInterface $adapter
     * @return Identity
     */
    protected function createIdentity(AdapterInterface $adapter): Identity
    {
        $map = new $this->attribute_map_class($adapter->getAttributeMap(), $this->logger);
        $this->identity = new $this->identity_class($adapter, $map, $this->logger);
        return $this->identity;
    }


    /**
     * Authenticate
     *
     * @return  bool
     */
    public function requireOne(): bool
    {
        $result = false;

        foreach ($this->adapter as $name => $adapter) {
            try {
                if ($adapter->authenticate()) {
                    $this->createIdentity($adapter);

                    $this->logger->info("identity [{$this->identity->getIdentifier()}] authenticated over adapter [{$name}]", [
                        'category' => get_class($this)
                    ]);
                    $_SERVER['REMOTE_USER'] = $this->identity->getIdentifier();

                    return true;
                }
            } catch (\Exception $e) {
                $this->logger->error("failed authenticate user, unexcepted exception was thrown", [
                    'category' => get_class($this),
                    'exception'=> $e
                ]);
            }

            $this->logger->debug("auth adapter [{$name}] failed", [
                'category' => get_class($this)
            ]);
        }

        $this->logger->warning("all authentication adapter have failed", [
            'category' => get_class($this)
        ]);

        return false;
    }


    /**
     * Get identity
     *
     * @return Identity
     */
    public function getIdentity(): Identity
    {
        if (!$this->isAuthenticated()) {
            throw new Exception('no valid authentication yet');
        } else {
            return $this->identity;
        }
    }


    /**
     * Check if valid identity exists
     *
     * @return bool
     */
    public function isAuthenticated(): bool
    {
        return ($this->identity instanceof Identity);
    }
}
