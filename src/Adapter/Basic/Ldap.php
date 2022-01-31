<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @copyright   Copryright (c) 2015-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth\Adapter\Basic;

use Dreamscapes\Ldap\Core\Ldap as LdapServer;
use Micro\Auth\Adapter\AdapterInterface;
use Micro\Auth\IdentityInterface;
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
     * Uri.
     *
     * @var string
     */
    protected $uri = 'ldap://127.0.0.1:389';

    /**
     * Binddn.
     *
     * @var string
     */
    protected $binddn;

    /**
     * Bindpw.
     *
     * @var string
     */
    protected $bindpw;

    /**
     * Basedn.
     *
     * @var string
     */
    protected $basedn = '';

    /**
     * tls.
     *
     * @var bool
     */
    protected $tls = false;

    /**
     *  Options.
     *
     * @var array
     */
    protected $options = [];

    /**
     * Init.
     */
    public function __construct(LdapServer $ldap, LoggerInterface $logger, ?Iterable $config = null, ?Iterable $ldap_options = null)
    {
        parent::__construct($logger);
        $this->ldap = $ldap;
        $this->setLdapOptions($ldap_options);
        $this->setOptions($config);
        $this->setup();
    }

    /**
     * {@inheritdoc}
     */
    protected function setup(): AdapterInterface
    {
        $this->logger->debug('connect to ldap server ['.$this->uri.']', [
            'category' => get_class($this),
        ]);

        if (null === $this->binddn) {
            $this->logger->warning('no binddn set for ldap connection, you should avoid anonymous bind', [
                'category' => get_class($this),
            ]);
        }

        if (false === $this->tls && 'ldaps' !== substr($this->uri, 0, 5)) {
            $this->logger->warning('neither tls nor ldaps enabled for ldap connection, it is strongly reccommended to encrypt ldap connections', [
                'category' => get_class($this),
            ]);
        }

        $this->ldap->connect($this->uri);

        foreach ($this->options as $opt => $value) {
            $this->ldap->setOption(constant($opt), $value);
        }

        if (true === $this->tls) {
            $this->ldap->startTls();
        }

        $this->logger->info('bind to ldap server ['.$this->uri.'] with binddn ['.$this->binddn.']', [
            'category' => get_class($this),
        ]);

        $this->ldap->bind($this->binddn, $this->bindpw);

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function setOptions(?Iterable $config = null): AdapterInterface
    {
        if (null === $config) {
            return $this;
        }

        foreach ($config as $option => $value) {
            switch ($option) {
                case 'account_filter':
                    $this->{$option} = $value;
                    unset($config[$option]);

                    break;
            }
        }

        parent::setOptions($config);

        return $this;
    }

    /**
     * Set ldap options.
     */
    public function setLdapOptions(?Iterable $config = null): AdapterInterface
    {
        if (null === $config) {
            return $this;
        }

        foreach ($config as $option => $value) {
            switch ($option) {
                case 'options':
                    $this->options = $value;
                    unset($config[$option]);

                    break;
                case 'uri':
                case 'binddn':
                case 'bindpw':
                case 'basedn':
                case 'account_filter':
                    $this->{$option} = (string) $value;
                    unset($config[$option]);

                    break;
                case 'tls':
                    $this->tls = (bool) $value;
                    unset($config[$option]);

                    break;
                default:
                    throw new InvalidArgumentException('invalid ldap option '.$option.' given');
            }
        }

        return $this;
    }

    /**
     * LDAP Auth.
     */
    public function plainAuth(string $username, string $password)
    {
        $search[] = 'dn';
        $search[] = $this->identity_attribute;

        $esc_username = ldap_escape($username);
        $filter = htmlspecialchars_decode(sprintf($this->account_filter, $esc_username));
        $result = $this->ldap->ldapSearch($this->basedn, $filter, ['dn', $this->identity_attribute]);

        if (0 === $result->countEntries()) {
            $this->logger->warning("no object found with ldap filter [{$filter}]", [
                'category' => get_class($this),
            ]);

            return null;
        }
        if ($result->countEntries() > 1) {
            $this->logger->warning("more than one object found with ldap filter [{$filter}]", [
                'category' => get_class($this),
            ]);

            return null;
        }

        $entries = $result->getEntries();

        $dn = $entries[0]['dn'];
        $this->logger->info("found ldap user [{$dn}] with filter [{$filter}]", [
            'category' => get_class($this),
        ]);

        $result = $this->ldap->bind($dn, $password);

        $this->logger->info("bind ldap user [{$dn}]", [
            'category' => get_class($this),
            'result' => $result,
        ]);

        if (false === $result) {
            return null;
        }

        return $this->prepareRawObject($entries[0]);
    }

    /**
     * Get attributes.
     */
    public function getAttributes(IdentityInterface $identity): array
    {
        $search = array_column($this->map, 'attr');
        $filter = htmlspecialchars_decode(sprintf($this->account_filter, $identity->getIdentifier()));

        $this->logger->debug("fetch ldap object attributes with [$filter]", [
            'category' => get_class($this),
        ]);

        $result = $this->ldap->ldapSearch($this->basedn, $filter, $search);

        $entries = $result->getEntries();
        $attributes = $entries[0];

        $this->logger->info('received ldap object attributes', [
            'category' => get_class($this),
            'params' => $attributes,
        ]);

        return $this->prepareRawObject($attributes);
    }

    /**
     * Prepare object.
     */
    protected function prepareRawObject(array $result): array
    {
        $object = [];
        foreach ($result as $key => $attr) {
            if ('count' === $key) {
                continue;
            }
            if ('dn' === $key) {
                $object['entrydn'] = $attr;
            } elseif (!is_int($key)) {
                if (1 === $attr['count']) {
                    if (preg_match('~[^\x20-\x7E\t\r\n]~', $attr[0]) > 0) {
                        $object[$key] = base64_encode($attr[0]);
                    } else {
                        $object[$key] = $attr[0];
                    }
                } else {
                    $val = $attr;
                    unset($val['count']);

                    foreach ($val as $v) {
                        if (preg_match('~[^\x20-\x7E\t\r\n]~', $v) > 0) {
                            $object[$key][] = base64_encode($v);
                        } else {
                            $object[$key][] = $v;
                        }
                    }
                }
            }
        }

        return $object;
    }
}
