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

package org.xipki.remotep11.server.impl;

import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.p11.P11CryptService;

/**
 * @author Lijun Liao
 */

public class LocalP11CryptServicePool
{
    private static final Logger LOG = LoggerFactory.getLogger(LocalP11CryptServicePool.class);

    public static final int version = 2;

    private SecurityFactory securityFactory;
    private String defaultPkcs11ModuleName;
    private Map<String, P11CryptService> p11CryptServices = new HashMap<>();

    public LocalP11CryptServicePool()
    {
    }

    public void setSecurityFactory(
            final SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    private boolean initialized = false;
    public void init()
    throws Exception
    {
        if(initialized)
        {
            return;
        }

        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        try
        {
            if(securityFactory == null)
            {
                throw new IllegalStateException("securityFactory is not configured");
            }

            this.defaultPkcs11ModuleName = securityFactory.getDefaultPkcs11ModuleName();
            Set<String> moduleNames = securityFactory.getPkcs11ModuleNames();
            for(String moduleName : moduleNames)
            {
                P11CryptService p11Service = securityFactory.getP11CryptService(moduleName);
                if(p11Service != null)
                {
                    p11CryptServices.put(moduleName, p11Service);
                }
            }

            initialized = true;
        }catch(Exception e)
        {
            LOG.error("exception thrown. {}: {}", e.getClass().getName(), e.getMessage());
            LOG.debug("exception thrown", e);
            throw e;
        }
    }

    public P11CryptService getP11CryptService(
            String moduleName)
    {
        if(moduleName == null || SecurityFactory.DEFAULT_P11MODULE_NAME.equalsIgnoreCase(moduleName))
        {
            moduleName = defaultPkcs11ModuleName;
        }
        P11CryptService p11Service = p11CryptServices.get(moduleName);
        return p11Service;
    }

    public int getVersion()
    {
        return version;
    }

}
