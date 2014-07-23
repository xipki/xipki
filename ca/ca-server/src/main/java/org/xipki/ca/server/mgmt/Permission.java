/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt;

import java.util.Set;

/**
 * @author Lijun Liao
 */

public enum Permission
{
    ENROLL_CERT ("enroll"),
    REVOKE_CERT ("revoke"),
    UNREVOKE_CERT ("unrevoke"),
    REMOVE_CERT ("remove"),
    KEY_UPDATE ("key-update"),
    GEN_CRL ("gen-crl"),
    GET_CRL ("get-crl"),
    CROSS_CERT_ENROLL ("enroll-cross"),
    ALL("all");

    private String permission;
    private Permission(String permission)
    {
        this.permission = permission;
    }

    public String getPermission()
    {
        return permission;
    }

    public static Permission getPermission(String permission)
    {
        for(Permission p : values())
        {
            if(p.permission.equalsIgnoreCase(permission))
            {
                return p;
            }
        }

        return null;
    }

    public static String toString(Set<Permission> permissions)
    {
        if(permissions == null || permissions.isEmpty())
        {
            return null;
        }

        StringBuilder sb = new StringBuilder();
        for(Permission p : permissions)
        {
            sb.append(",");
            sb.append(p.getPermission());
        }
        return sb.substring(1); // remove the leading ",".
    }

}
