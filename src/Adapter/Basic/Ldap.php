<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @copyright   Copryright (c) 2015-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth\Adapter\Basic;

use Micro\Auth\Adapter\AdapterInterface;
use Micro\Auth\Exception;
use Micro\Auth\Ldap as LdapServer;
use Psr\Log\LoggerInterface;

class Ldap extends AbstractBasic
{
    /**
     * Ldap.
     *
     * @var LdapServer
     */
    protected $ldap;

    /**
     * LDAP DN.
     *
     * @var string
     */
    protected $ldap_dn;

    /**
     * Account filter.
     *
     * @var string
     */
    protected $account_filter = '(uid=%s)';

    /**
     * Logger.
     *
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * Init.
     *
     * @param LdapServer      $ldap
     * @param LoggerInterface $logger
     * @param iterable        $config
     */
    public function __construct(LdapServer $ldap, LoggerInterface $logger, ?Iterable $config = null)
    {
        parent::__construct($logger);
        $this->ldap = $ldap;
        $this->setOptions($config);
    }

    /**
     * Setup.
     */
    public function setup(): bool
    {
        $this->ldap->connect();

        return true;
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
                case 'account_filter':
                    $this->account_filter = $value;
                    unset($config[$option]);

                break;
            }
        }

        parent::setOptions($config);

        return $this;
    }

    /**
     * LDAP Auth.
     *
     * @param string $username
     * @param string $password
     *
     * @return bool
     */
    public function plainAuth(string $username, string $password): bool
    {
        $resource = $this->ldap->getResource();

        $esc_username = ldap_escape($username);
        $filter = htmlspecialchars_decode(sprintf($this->account_filter, $esc_username));
        $result = ldap_search($resource, $this->ldap->getBase(), $filter, ['dn', $this->identity_attribute]);
        $entries = ldap_get_entries($resource, $result);

        if (0 === $entries['count']) {
            $this->logger->warning("user not found with ldap filter [{$filter}]", [
                'category' => get_class($this),
            ]);

            return false;
        }
        if ($entries['count'] > 1) {
            $this->logger->warning("more than one user found with ldap filter [{$filter}]", [
                'category' => get_class($this),
            ]);

            return false;
        }

        $dn = $entries[0]['dn'];
        $this->logger->info("found ldap user [{$dn}] with filter [{$filter}]", [
            'category' => get_class($this),
        ]);

        $result = ldap_bind($resource, $dn, $password);
        $this->logger->info("bind ldap user [{$dn}]", [
            'category' => get_class($this),
            'result' => $result,
        ]);

        if (false === $result) {
            return false;
        }

        if (!isset($entries[0][$this->identity_attribute])) {
            throw new Exception\IdentityAttributeNotFound('identity attribute not found');
        }

        $this->identifier = $entries[0][$this->identity_attribute][0];
        $this->ldap_dn = $dn;

        return true;
    }

    /**
     * Get attributes.
     *
     * @return array
     */
    public function getAttributes(): array
    {
        $search = array_column($this->map, 'attr');
        $result = ldap_read($this->ldap->getResource(), $this->ldap_dn, '(objectClass=*)', $search);
        $entries = ldap_get_entries($this->ldap->getResource(), $result);
        $attributes = $entries[0];

        $this->logger->info("get ldap user [{$this->ldap_dn}] attributes", [
            'category' => get_class($this),
            'params' => $attributes,
        ]);

        return $attributes;
    }
}
