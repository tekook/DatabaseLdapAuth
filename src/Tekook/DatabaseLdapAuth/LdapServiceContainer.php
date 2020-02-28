<?php


namespace Tekook\DatabaseLdapAuth;


use App\Models\LdapService;
use App\Services\Auth\Contracts\LdapAuthenticatable;
use LdapRecord\Connection;

class LdapServiceContainer
{

    protected ?LdapService $service = null;
    protected ?Connection $connection = null;
    protected string $model;

    public function __construct(string $model)
    {
        $this->model = $model;
    }

    /**
     * @param \App\Services\Auth\Contracts\LdapAuthenticatable|null $model
     *
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function modelQuery(LdapAuthenticatable $model = null)
    {
        $model = $model ?: $this->createModel();
        return $model->query();
    }

    /**
     * Classname of the model to use.
     *
     * @return LdapAuthenticatable
     */
    public function createModel()
    {
        return new $this->model;
    }

    /**
     * gets class name of the model.
     *
     * @return string
     */
    public function getModel()
    {
        return $this->model;
    }

    /**
     * Gets current ldap service
     *
     * @return \App\Models\LdapService|null
     */
    public function getService()
    {
        return $this->service;
    }

    /**
     * Sets the current ldap service and initializes a new Connection to it.
     *
     * @param \App\Models\LdapService $service
     */
    protected function setService(?LdapService $service)
    {
        $this->service = $service;
        $this->connection = is_null($service) ? null : new Connection($service->toConfigArray());
    }

    /**
     * Get current connection.
     *
     * @return \LdapRecord\Connection|null
     */
    public function getConnection()
    {
        return $this->connection;
    }

    /**
     * Checks if $this->>connection is not null.
     *
     * @return bool
     */
    public function canConnect()
    {
        return !is_null($this->connection);
    }

    /**
     * @param array $credentials
     */
    public function setServiceFromCredentials(array $credentials)
    {
        $column = $this->createModel()->getLdapServiceIdentifierColumn();
        if (isset($credentials[$column])) {
            $this->setService(null);
        } else {
            $this->setService($this->getServiceById($credentials[$column]));
        }
    }

    /**
     * @param $id
     *
     * @return LdapService|null
     */
    protected function getServiceById($id)
    {
        return $id == null ? null : LdapService::find($id);
    }


    /**
     * @param \App\Services\Auth\Contracts\LdapAuthenticatable $user
     */
    public function setServiceFromAuthenticatable(LdapAuthenticatable $user)
    {
        $this->setService($this->getServiceById($user->getLdapServiceIdentifier()));
    }
}
