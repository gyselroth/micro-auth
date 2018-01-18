<?php

declare(strict_types=1);

/**
 * balloon
 *
 * @copyright   Copryright (c) 2012-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     GPL-3.0 https://opensource.org/licenses/GPL-3.0
 */

namespace Micro\Auth;

interface AttributeMapInterface
{
    /**
     * Get attribute map.
     *
     * @return Iterable
     */
    public function getAttributeMap(): Iterable;

    /**
     * Prepare attributes.
     *
     * @param array $data
     *
     * @return array
     */
    public function map(array $data): array;
}