<?php


namespace Tekook\DatabaseLdapAuth;


use App\Services\Auth\Contracts\LdapAuthenticatable;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class LdapImporter
{
    protected bool $syncPasswords;
    protected array $syncAttributes;
    protected EloquentUserProvider $provider;
    protected LdapServiceContainer $container;

    public function __construct(
        LdapServiceContainer $container,
        EloquentUserProvider $provider,
        bool $syncPasswords,
        array $syncAttributes
    ) {
        $this->container = $container;
        $this->provider = $provider;
        $this->syncPasswords = $syncPasswords;
        $this->syncAttributes = $syncAttributes;
    }

    /**
     * @param \App\Services\Auth\LdapEntity $entity
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     * @throws \Illuminate\Validation\ValidationException
     */
    public function run(LdapEntity $entity)
    {
        $model = $this->container->createModel();
        $search = [
            $model->getLdapServiceIdentifierColumn() => $this->container->getService()->id,
            $model->getLdapSidColumn()               => $entity->sid->getValue(),
        ];
        $model = $this->provider->retrieveByCredentials($search);
        if ($model == null) {
            $this->checkForExisting($entity);
            // We found no model, create one with random password, since there are not yet validated.
            $user = $this->container->createModel();
            $user->{$user->getLdapSidColumn()} = $entity->sid->getValue();
            $user->{$user->getLdapServiceIdentifierColumn()} = $this->container->getService()->id;
            foreach ($this->syncAttributes as $ldapKey => $modelKey) {
                $user->{$modelKey} = $entity->{$ldapKey};
            }
            $user->password = Str::random();
            $user->save();
            return $user;
        } else {
            return $model;
        }
    }

    /**
     * @param \App\Services\Auth\LdapEntity $entity
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function checkForExisting(LdapEntity $entity)
    {
        if ($this->container->modelQuery()->where('email', $entity->mail)->count() > 0) {
            throw ValidationException::withMessages([
                'email' => [trans('auth.otherProvider')],
            ]);
        }
    }

    /**
     * To be called after successfully authenticating the user to store its name and password.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @param \App\Services\Auth\LdapEntity $entity
     * @param array $credentials
     */
    public function sync(Authenticatable $user, LdapEntity $entity, array $credentials)
    {
        foreach ($this->syncAttributes as $ldapKey => $modelKey) {
            $user->{$modelKey} = $entity->{$ldapKey};
        }
        if ($this->syncPasswords) {
            // We authenticated the user correctly, so it is save to store to password.
            $user->password = Hash::make($credentials['password']);
        } else {
            $user->password = Str::random();
        }
        $user->save();
    }
}
