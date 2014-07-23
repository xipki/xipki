/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server;

import java.util.Set;

import org.xipki.ca.common.CertBasedRequestorInfo;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.ca.server.mgmt.Permission;

/**
 * @author Lijun Liao
 */

public class CmpRequestorInfo extends CertBasedRequestorInfo
{
    private Set<Permission> permissions;
    private Set<String> profiles;

    public CmpRequestorInfo(String name, X509CertificateWithMetaInfo certificate, boolean ra)
    {
        super(name, certificate, ra);
    }

    public Set<Permission> getPermissions()
    {
        return permissions;
    }

    public void setPermissions(Set<Permission> permissions)
    {
        this.permissions = permissions;
    }

    public Set<String> getProfiles()
    {
        return profiles;
    }

    public void setProfiles(Set<String> profiles)
    {
        this.profiles = profiles;
    }

}
