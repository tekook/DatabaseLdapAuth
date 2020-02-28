<?php


namespace Tekook\DatabaseLdapAuth;


use App\Services\Auth\Contracts\LdapAuthenticatable;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Support\Str;

class LdapRetriever
{
    protected LdapServiceContainer $container;
    protected array $columns = ['dn', 'cn', 'objectsid', 'mail'];

    public function __construct(LdapServiceContainer $container)
    {
        $this->container = $container;
    }

    /**
     * Checks the given LdapService for an entity with the given credentials.
     * Returns the entity if credentials match, null if no entity was found and false if the credentials are wrong.
     *
     * @param array $credentials
     *
     * @return \App\Services\Auth\LdapEntity|null
     */
    public function findByCredentials(array $credentials)
    {
        $query = $this->container->getConnection()->query();
        $query->where([
            ['objectclass', '=', 'top'],
            ['objectclass', '=', 'person'],
            ['objectclass', '=', 'organizationalperson'],
            ['objectclass', '=', 'user'],
        ]);
        $column = $this->container->createModel()->getLdapServiceIdentifierColumn();
        foreach ($credentials as $key => $value) {
            if (Str::contains($key, 'password')) {
                continue;
            }
            if (Str::lower($column) == Str::lower($key)) {
                continue;
            }
            if ($key === 'email') {
                $key = 'mail';
            }

            if (is_array($value) || $value instanceof Arrayable) {
                $query->whereIn($key, $value);
            } else {
                $query->where($key, $value);
            }
        }
        $model = $query->first($this->columns);
        return $model == null ? null : new LdapEntity((array)$model);
    }

    /**
     * @param \App\Services\Auth\Contracts\LdapAuthenticatable $user
     *
     * @return \App\Services\Auth\LdapEntity|null
     */
    public function findByAuthenticatable(LdapAuthenticatable $user)
    {
        $this->container->setServiceFromAuthenticatable($user);
        return $this->findBySid($user->getLdapSid());
    }

    /**
     * @param string $sid
     *
     * @return \App\Services\Auth\LdapEntity|null
     */
    public function findBySid(string $sid)
    {
        $model = $this->container->getConnection()->query()->findBy('objectsid', $sid, $this->columns);
        return $model == null ? null : new LdapEntity($model);
    }

    /**
     * @param \App\Services\Auth\LdapEntity $entity
     * @param array $credentials
     *
     * @return bool
     * @throws \LdapRecord\Auth\BindException
     * @throws \LdapRecord\Auth\PasswordRequiredException
     * @throws \LdapRecord\Auth\UsernameRequiredException
     * @throws \LdapRecord\ConnectionException
     */
    public function validate(LdapEntity $entity, array $credentials)
    {
        return $this->container->getConnection()->auth()->attempt($entity->dn, $credentials['password']);
    }
}
