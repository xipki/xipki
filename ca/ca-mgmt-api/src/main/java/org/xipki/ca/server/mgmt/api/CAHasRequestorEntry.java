/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.api;

import java.io.IOException;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CAHasRequestorEntry implements Serializable
{
    private String requestorName;
    private boolean ra;
    private Set<Permission> permissions;
    private Set<String> profiles;

    public CAHasRequestorEntry(String requestorName)
    {
        ParamChecker.assertNotEmpty("requestorName", requestorName);
        this.requestorName = requestorName;
        this.serialVersion = SERIAL_VERSION;
    }

    public boolean isRa()
    {
        return ra;
    }

    public void setRa(boolean ra)
    {
        this.ra = ra;
    }

    public Set<Permission> getPermissions()
    {
        return permissions;
    }

    public void setPermissions(Set<Permission> permissions)
    {
        this.permissions = Collections.unmodifiableSet(permissions);
    }

    public String getRequestorName()
    {
        return requestorName;
    }

    public void setProfiles(Set<String> profiles)
    {
        this.profiles = Collections.unmodifiableSet(profiles);
    }

    public Set<String> getProfiles()
    {
        return profiles;
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("requestor: ").append(requestorName).append(", ");
        sb.append("ra: ").append(ra).append(", ");
        sb.append("profiles: ").append(profiles).append(", ");
        sb.append("permissions: ").append(Permission.toString(permissions));
        return sb.toString();
    }

    // ------------------------------------------------
    // Customized serialization
    // ------------------------------------------------
    private static final long serialVersionUID = 1L;

    private static final String SR_serialVersion = "serialVersion";
    private static final double SERIAL_VERSION = 1.0;

    private static final String SR_requestorName = "requestorName";
    private static final String SR_ra = "ra";
    private static final String SR_permissions = "permissions";
    private static final String SR_profiles = "profiles";

    private double serialVersion;

    private void writeObject(java.io.ObjectOutputStream out)
    throws IOException
    {
        final Map<String, Object> serialMap = new HashMap<String, Object>();

        serialMap.put(SR_serialVersion, serialVersion);
        serialMap.put(SR_requestorName, requestorName);
        serialMap.put(SR_ra, ra);
        serialMap.put(SR_permissions, permissions);
        serialMap.put(SR_profiles, profiles);

        out.writeObject(serialMap);
    }

    @SuppressWarnings("unchecked")
    private void readObject(java.io.ObjectInputStream in)
    throws IOException, ClassNotFoundException
    {
        final Map<String, Object> serialMap = (Map<String, Object>) in.readObject();
        serialVersion = (double) serialMap.get(SR_serialVersion);

        requestorName = (String) serialMap.get(SR_requestorName);
        ra = (boolean) serialMap.get(SR_ra);
        permissions = (Set<Permission>) serialMap.get(SR_permissions);
        profiles = (Set<String>) serialMap.get(SR_profiles);
    }
}
