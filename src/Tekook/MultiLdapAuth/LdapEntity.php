<?php


namespace Tekook\DatabaseLdapAuth;


use LdapRecord\Models\Attributes\Sid;

class LdapEntity
{
    public Sid $sid;
    public string $dn;
    public string $cn;
    public string $mail;

    public function __construct(array $entity)
    {
        $this->sid = new Sid($entity['objectsid'][0]);
        $this->dn = $entity['dn'];
        $this->cn = $entity['cn'][0];
        $this->mail = $entity['mail'][0];
    }
}
