/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.api.profile;

/**
 * @author Lijun Liao
 */

public enum SpecialCertProfileBehavior
{
    gematik_gSMC_K;

    public static final String PARAMETER_MAXLIFTIME = "maxLifetime";

    public static SpecialCertProfileBehavior getInstance(String behavior)
    {
        for(SpecialCertProfileBehavior b : values())
        {
            if(b.name().equalsIgnoreCase(behavior))
            {
                return b;
            }
        }

        return null;
    }
}
