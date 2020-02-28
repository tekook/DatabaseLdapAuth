<?php


namespace Tekook\DatabaseLdapAuth;


use App\Services\Auth\Contracts\LdapAuthenticatable;
use Exception;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use LdapRecord\Auth\BindException;

class LdapServiceUserProvider implements UserProvider
{

    protected LdapRetriever $retriever;
    protected LdapImporter $importer;
    protected EloquentUserProvider $eloquent;
    protected array $config;

    protected bool $fallback = false;
    protected bool $syncPasswords = false;
    protected array $syncAttributes = [];
    protected LdapServiceContainer $container;

    public function __construct(EloquentUserProvider $eloquent, array $config)
    {
        $this->eloquent = $eloquent;
        $this->config = $config;
        $this->fallback = $config['fallback'];
        $this->syncPasswords = $config['sync_passwords'];
        $this->syncAttributes = $config['sync_attributes'];
        $this->container = new LdapServiceContainer($config['model']);
        $this->importer = new LdapImporter($this->container, $this->eloquent, $this->syncPasswords,
            $this->syncAttributes);
        $this->retriever = new LdapRetriever($this->container);
    }

    /**
     * @inheritDoc
     */
    public function retrieveByToken($identifier, $token)
    {
        return $this->eloquent->retrieveByToken($identifier, $token);
    }

    /**
     * @inheritDoc
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        $this->eloquent->updateRememberToken($user, $token);
    }

    /**
     * @inheritDoc
     *
     * @param array $credentials
     *
     * @return \App\Models\User|\Illuminate\Contracts\Auth\Authenticatable|\Illuminate\Database\Eloquent\Model|\Illuminate\Database\Eloquent\Relations\HasMany|object|null
     * @throws \Illuminate\Validation\ValidationException
     */
    public function retrieveByCredentials(array $credentials)
    {
        $this->container->setServiceFromCredentials($credentials);
        if ($this->container->canConnect()) {
            try {
                $entity = $this->retriever->findByCredentials($credentials);
                if ($entity === null) {
                    // no record found
                    return null;
                }
                return $this->importer->run($entity);
            } catch (BindException $e) {
                // could not reach ldap server, continuing with fallback (if enabled)
            }

            if ($this->container->getService()->can_fallback) {
                // We found nothing and can fallback to normal auth.
                return $this->eloquent->retrieveByCredentials($credentials);
            } else {
                // since we found an LdapService and it is not allowed to fallback -> fail
                return null;
            }
        }


        if ($this->fallback) {
            // No LdapService provided and we can fallback to normal auth.
            return $this->eloquent->retrieveByCredentials($credentials);
        }

        // nothing matched -> not authed!
        return null;
    }


    /**
     * @inheritDoc
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        if ($user instanceof LdapAuthenticatable) {
            if ($user->getLdapServiceIdentifier() == null) {
                return $this->eloquent->validateCredentials($user, $credentials);
            }
            try {
                $entity = $this->retriever->findByAuthenticatable($user);
                if (!$this->container->canConnect()) {
                    return false;
                }
                if ($this->retriever->validate($entity, $credentials)) {
                    $this->importer->sync($user, $entity, $credentials);
                    return true;
                }
                return false;
            } catch (Exception $e) {
                if ($this->container->getService()->can_fallback) {
                    return $this->eloquent->validateCredentials($user, $credentials);
                }
            }
        }
        return false;
    }


    /**
     * @inheritDoc
     */
    public function retrieveById($identifier)
    {
        return $this->eloquent->retrieveById($identifier);
    }
}
