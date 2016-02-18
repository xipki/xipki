/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * (version 3 or later at your option)
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.ca.server.mgmt;

import org.xipki.ca.api.profile.CertProfile;
import org.xipki.ca.api.profile.SpecialCertProfileBehavior;
import org.xipki.ca.common.CertProfileException;
import org.xipki.ca.server.certprofile.DefaultCertProfile;
import org.xipki.ca.server.mgmt.api.CertProfileEntry;
import org.xipki.security.common.EnvironmentParameterResolver;
import org.xipki.security.common.ParamChecker;

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
