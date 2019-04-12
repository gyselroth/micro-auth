<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @copyright   Copryright (c) 2015-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth\Adapter;

use InvalidArgumentException;

abstract class AbstractAdapter implements AdapterInterface
{
    /**
     * Identity.
     *
     * @var string
     */
    protected $identifier;

    /**
     * attribute sync cache.
     *
     * @var int
     */
    protected $attr_sync_cache = 0;

    /**
     * attribute map.
     *
     * @var iterable
     */
    protected $map = [];

    /**
     * Identity attribute.
     *
     * @var string
     */
    protected $identity_attribute = 'uid';

    /**
     * Setup.
     *
     * @return bool
     */
    public function setup(): bool
    {
        return true;
    }

    /**
     * Get attribute sync cache.
     *
     * @return int
     */
    public function getAttributeSyncCache(): int
    {
        return $this->attr_sync_cache;
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
                case 'map':
                    $this->map = $value;

                break;
                case 'attr_sync_cache':
                    $this->attr_sync_cache = (int) $value;

                break;
                case 'identity_attribute':
                    $this->identity_attribute = $value;

                break;
                default:
                    throw new InvalidArgumentException('unknown option '.$option.' given');
            }
        }

        return $this;
    }

    /**
     * Get identifier.
     *
     * @return string
     */
    public function getIdentityAttribute(): string
    {
        return $this->identity_attribute;
    }

    /**
     * Get identifier.
     *
     * @return string
     */
    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * Get attribute map.
     *
     * @return iterable
     */
    public function getAttributeMap(): Iterable
    {
        return $this->map;
    }
}
