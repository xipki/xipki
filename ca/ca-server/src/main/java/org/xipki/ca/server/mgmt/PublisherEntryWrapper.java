/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
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

import java.util.HashMap;
import java.util.Map;

import org.xipki.audit.api.AuditLoggingServiceRegister;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.common.CertPublisherException;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.publisher.OCSPCertPublisher;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.ConfPairs;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class PublisherEntryWrapper
{
    private static final Map<String, IdentifiedCertPublisher> publisherPool = new HashMap<>();

    private final PublisherEntry entry;
    private final IdentifiedCertPublisher certPublisher;

    public PublisherEntryWrapper(PublisherEntry entry, PasswordResolver passwordResolver,
            Map<String, DataSourceWrapper> dataSourceMap)
    throws CertPublisherException
    {
        ParamChecker.assertNotNull("entry", entry);
        this.entry = entry;
        this.certPublisher = createCertPublisher(entry, passwordResolver, dataSourceMap);
    }

    public PublisherEntry getEntry()
    {
        return entry;
    }

    public String getName()
    {
        return entry.getName();
    }

    public static IdentifiedCertPublisher createCertPublisher(PublisherEntry entry,
            PasswordResolver passwordResolver, Map<String, DataSourceWrapper> dataSourceMap)
    throws CertPublisherException
    {
        final String type = entry.getType();
        final String conf = entry.getConf();
        IdentifiedCertPublisher cachedPublisher = publisherPool.get(type + conf);
        if(cachedPublisher != null)
        {
            return cachedPublisher;
        }

        CertPublisher realPublisher;
        if("ocsp".equalsIgnoreCase(type) ||
                "java:org.xipki.ca.server.publisher.DefaultCertPublisher".equals(type) || // for backwards compatibility
                "java:org.xipki.ca.server.publisher.OCSPCertPublisher".equals(type))
        {
            realPublisher = new OCSPCertPublisher();
        }
        else if(type.toLowerCase().startsWith("java:"))
        {
            String className = type.substring("java:".length());
            try
            {
                Class<?> clazz = Class.forName(className);
                realPublisher = (CertPublisher) clazz.newInstance();
            }catch(Exception e)
            {
                throw new CertPublisherException("invalid type " + type + ", " + e.getMessage());
            }
        }
        else
        {
            throw new CertPublisherException("invalid type " + type);
        }

        String datasourceName = null;
        ConfPairs confPairs = null;
        try
        {
            confPairs = new ConfPairs(conf);
            datasourceName = confPairs.getValue("datasource");
        }catch(Exception e)
        {
        }

        DataSourceWrapper ocspDataSource = null;
        if(datasourceName != null)
        {
            ocspDataSource = dataSourceMap.get(datasourceName);
        }

        IdentifiedCertPublisher certPublisher = new IdentifiedCertPublisher(entry.getName(), realPublisher);
        certPublisher.initialize(conf, passwordResolver, ocspDataSource);

        return certPublisher;
    }

    @Override
    public String toString()
    {
        return entry.toString();
    }

    public void setAuditServiceRegister(AuditLoggingServiceRegister serviceRegister)
    {
        certPublisher.setAuditServiceRegister(serviceRegister);
    }

    public IdentifiedCertPublisher getCertPublisher()
    {
        return certPublisher;
    }

}
