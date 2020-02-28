<?php


namespace Tekook\DatabaseLdapAuth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Interface LdapAuthenticatable
 *
 * @package App\Services\Auth\Contracts
 */
interface LdapAuthenticatable extends Authenticatable
{
    /**
     * Gets the ID of the LdapService
     *
     * @return mixed
     * @see \App\Models\LdapService
     */
    public function getLdapServiceIdentifier();

    /**
     * Gets the name of the column of the Ldap Identifier.
     *
     * @return mixed
     * @see \App\Models\LdapService
     *
     */
    public function getLdapServiceIdentifierColumn();

    /**
     * Gets the name of the column which contains the SID.
     *
     * @return mixed
     */
    public function getLdapSidColumn();

    /**
     * Gets the SID of the User.
     *
     * @return mixed
     */
    public function getLdapSid();

}
