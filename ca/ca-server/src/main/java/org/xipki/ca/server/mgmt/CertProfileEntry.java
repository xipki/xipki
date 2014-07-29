/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt;

import org.xipki.ca.api.profile.CertProfile;
import org.xipki.ca.api.profile.CertProfileException;
import org.xipki.ca.api.profile.SpecialCertProfileBehavior;
import org.xipki.ca.server.IdentifiedCertProfile;
import org.xipki.ca.server.certprofile.DefaultCertProfile;
import org.xipki.security.common.EnvironmentParameterResolver;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CertProfileEntry
{
    private final String name;
    private String type;
    private String conf;
    private IdentifiedCertProfile certProfile;
    private EnvironmentParameterResolver envParamResolver;

    public CertProfileEntry(String name)
    {
        ParamChecker.assertNotEmpty("name", name);
        this.name = name;
    }

    public String getName()
    {
        return name;
    }

    public String getType()
    {
        return type;
    }

    public void setType(String type)
    {
        ParamChecker.assertNotEmpty("type", type);

        if(type.equals(this.type) == false)
        {
            this.type = type;
            this.certProfile = null;
        }
    }

    public void setConf(String conf)
    {
        boolean same = (conf == null) ? this.conf == null : conf.equals(this.conf);
        if(same == false)
        {
            this.conf = conf;
            this.certProfile = null;
        }
    }

    public synchronized IdentifiedCertProfile getCertProfile()
    throws CertProfileException
    {
        if(this.certProfile != null)
        {
            return this.certProfile;
        }

        CertProfile underlyingCertProfile = null;
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
            }catch(ClassNotFoundException e)
            {
                throw new CertProfileException("invalid type " + type + ", ClassNotFoundException: " + e.getMessage());
            } catch (InstantiationException e)
            {
                throw new CertProfileException("invalid type " + type + ", InstantiationException: " + e.getMessage());
            } catch (IllegalAccessException e)
            {
                throw new CertProfileException("invalid type " + type + ", IllegalAccessException: " + e.getMessage());
            } catch(ClassCastException e)
            {
                throw new CertProfileException("invalid type " + type + ", ClassCastException: " + e.getMessage());
            }
        }
        else
        {
            throw new CertProfileException("invalid type " + type);
        }

        this.certProfile = new IdentifiedCertProfile(name, underlyingCertProfile);
        this.certProfile.initialize(conf);
        this.certProfile.setEnvironmentParameterResolver(envParamResolver);

        if(this.certProfile.getSpecialCertProfileBehavior() == SpecialCertProfileBehavior.gematik_gSMC_K)
        {
            String paramName = SpecialCertProfileBehavior.PARAMETER_MAXLIFTIME;
            String s = this.certProfile.getParameter(paramName);
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

        return this.certProfile;
    }

    public String getConf()
    {
        return conf;
    }

    public void setEnvironmentParamterResolver(
            EnvironmentParameterResolver envParamResolver)
    {
        this.envParamResolver = envParamResolver;
        if(certProfile != null)
        {
            certProfile.setEnvironmentParameterResolver(envParamResolver);
        }
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("name: ").append(name).append('\n');
        sb.append("type: ").append(type).append('\n');
        sb.append("conf: ").append(conf);
        return sb.toString();
    }
}
