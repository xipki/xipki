/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt;

import org.xipki.ca.api.profile.CertProfile;
import org.xipki.ca.api.profile.SpecialCertProfileBehavior;
import org.xipki.ca.common.CertProfileException;
import org.xipki.ca.server.certprofile.DefaultCertProfile;
import org.xipki.ca.server.mgmt.api.CertProfileEntry;
import org.xipki.common.EnvironmentParameterResolver;
import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CertProfileEntryWrapper
{
    private final CertProfileEntry entry;
    private final IdentifiedCertProfile certProfile;

    public CertProfileEntryWrapper(CertProfileEntry entry)
    throws CertProfileException
    {
        ParamChecker.assertNotNull("entry", entry);
        this.entry = entry;
        this.certProfile = createIdentifiedCertProfile(entry);
    }

    public CertProfileEntry getEntry()
    {
        return entry;
    }

    public String getName()
    {
        return entry.getName();
    }

    private static IdentifiedCertProfile createIdentifiedCertProfile(CertProfileEntry entry)
    throws CertProfileException
    {
        CertProfile underlyingCertProfile = null;

        final String type = entry.getType();
        final String conf = entry.getConf();

        if(type.equalsIgnoreCase("xml"))
        {
            underlyingCertProfile = new DefaultCertProfile();
        }
        else if(type.toLowerCase().startsWith("java:"))
        {
            String className = type.substring("java:".length());
            try
            {
                Class<?> clazz = Class.forName(className);
                underlyingCertProfile = (CertProfile) clazz.newInstance();
            }catch(ClassNotFoundException | InstantiationException  | IllegalAccessException | ClassCastException e)
            {
                throw new CertProfileException("invalid type " + type + ", " + e.getClass().getName() + ": " + e.getMessage());
            }
        }
        else
        {
            throw new CertProfileException("invalid type " + type);
        }

        IdentifiedCertProfile identifiedCertProfile = new IdentifiedCertProfile(entry.getName(), underlyingCertProfile);
        identifiedCertProfile.initialize(conf);

        if(identifiedCertProfile.getSpecialCertProfileBehavior() == SpecialCertProfileBehavior.gematik_gSMC_K)
        {
            String paramName = SpecialCertProfileBehavior.PARAMETER_MAXLIFTIME;
            String s = identifiedCertProfile.getParameter(paramName);
            if(s == null)
            {
                throw new CertProfileException("parameter " + paramName + " is not defined");
            }

            s = s.trim();
            int i;
            try
            {
                i = Integer.parseInt(s);
            }catch(NumberFormatException e)
            {
                throw new CertProfileException("invalid " + paramName + ": " + s);
            }
            if(i < 1)
            {
                throw new CertProfileException("invalid " + paramName + ": " + s);
            }
        }

        return identifiedCertProfile;
    }

    public void setEnvironmentParamterResolver(
            EnvironmentParameterResolver envParamResolver)
    {
        certProfile.setEnvironmentParameterResolver(envParamResolver);
    }

    public IdentifiedCertProfile getCertProfile()
    {
        return certProfile;
    }

    @Override
    public String toString()
    {
        return entry.toString();
    }
}
