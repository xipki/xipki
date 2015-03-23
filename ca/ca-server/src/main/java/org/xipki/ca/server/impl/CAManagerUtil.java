/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.ca.server.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CertprofileException;
import org.xipki.ca.api.EnvironmentParameterResolver;
import org.xipki.ca.server.mgmt.api.CAMgmtException;
import org.xipki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.ca.server.mgmt.api.X509CrlSignerEntry;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.ConfigurationException;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public class CAManagerUtil
{

    private static final Logger LOG = LoggerFactory.getLogger(CAManagerUtil.class);

    public static CmpResponderEntryWrapper createCmpResponder(
            CmpResponderEntry dbEntry, SecurityFactory securityFactory)
    throws CAMgmtException
    {
        CmpResponderEntryWrapper ret = new CmpResponderEntryWrapper();
        ret.setDbEntry(dbEntry);
        try
        {
            ret.initSigner(securityFactory);
        }catch(SignerException e)
        {
            final String message = "createCmpResponder";
            LOG.debug(message, e);
            throw new CAMgmtException(e.getMessage());
        }
        return ret;
    }

    public static X509CrlSignerEntryWrapper createX509CrlSigner(X509CrlSignerEntry dbEntry)
    throws CAMgmtException
    {
        X509CrlSignerEntryWrapper signer = new X509CrlSignerEntryWrapper();
        try
        {
            signer.setDbEntry(dbEntry);
        } catch (ConfigurationException e)
        {
            throw new CAMgmtException("ConfigurationException: " + e.getMessage());
        }
        return signer;
    }

    public static IdentifiedX509Certprofile createCertprofile(CertprofileEntry dbEntry,
            EnvironmentParameterResolver envParamResolver)
    {
        try
        {
            String realType = getRealCertprofileType(dbEntry.getType(), envParamResolver);
            IdentifiedX509Certprofile ret = new IdentifiedX509Certprofile(dbEntry, realType);
            ret.setEnvironmentParameterResolver(envParamResolver);
            ret.validate();
            return ret;
        }catch(CertprofileException e)
        {
            final String message = "could not initialize Certprofile " + dbEntry.getName() + ", ignore it";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            return null;
        }
    }

    private static String getRealCertprofileType(String certprofileType, EnvironmentParameterResolver envParameterResolver)
    {
        return getRealType(envParameterResolver.getParameterValue("certprofileType.map"), certprofileType);
    }

    private static String getRealPublisherType(String publisherType, EnvironmentParameterResolver envParameterResolver)
    {
        return getRealType(envParameterResolver.getParameterValue("publisherType.map"), publisherType);
    }

    private static String getRealType(String typeMap, String type)
    {
        if(typeMap == null)
        {
            return null;
        }

        typeMap = typeMap.trim();
        if(StringUtil.isBlank(typeMap))
        {
            return null;
        }

        CmpUtf8Pairs pairs;
        try
        {
            pairs = new CmpUtf8Pairs(typeMap);
        }catch(IllegalArgumentException e)
        {
            LOG.error("CA environment {}: '{}' is not valid CMP UTF-8 pairs",typeMap, type);
            return null;
        }
        return pairs.getValue(type);
    }

}
