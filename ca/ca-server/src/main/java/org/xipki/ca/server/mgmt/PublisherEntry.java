/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server.mgmt;

import java.util.HashMap;
import java.util.Map;

import org.xipki.audit.api.AuditLoggingService;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.server.IdentifiedCertPublisher;
import org.xipki.database.api.DataSource;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.ParamChecker;

public class PublisherEntry
{
    private static final Map<String, IdentifiedCertPublisher> publisherPool
        = new HashMap<String, IdentifiedCertPublisher>();

    private final String name;
    private String type;
    private String conf;

    private PasswordResolver passwordResolver;
    private DataSource dataSource;
    private IdentifiedCertPublisher certPublisher;
    private AuditLoggingService auditLoggingService;

    public PublisherEntry(String name)
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
            this.certPublisher = null;
        }
    }

    public void setConf(String conf)
    {
        boolean same = (conf == null) ? this.conf == null : conf.equals(this.conf);
        if(same == false)
        {
            this.conf = conf;
            this.certPublisher = null;
        }
    }

    public synchronized IdentifiedCertPublisher getCertPublisher()
    throws CertPublisherException
    {
        if(this.certPublisher != null)
        {
            return this.certPublisher;
        }

        IdentifiedCertPublisher cachedPublisher = publisherPool.get(type + conf);
        if(cachedPublisher != null)
        {
            this.certPublisher = cachedPublisher;
            return this.certPublisher;
        }

        CertPublisher realPublisher;
        if(type.toLowerCase().startsWith("java:"))
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

        this.certPublisher = new IdentifiedCertPublisher(name, realPublisher);
        this.certPublisher.initialize(conf, passwordResolver, dataSource);
        this.certPublisher.setAuditLoggingService(auditLoggingService);

        return this.certPublisher;
    }

    public String getConf()
    {
        return conf;
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

    public PasswordResolver getPasswordResolver()
    {
        return passwordResolver;
    }

    public void setPasswordResolver(PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }

    public DataSource getDataSource()
    {
        return dataSource;
    }

    public void setDataSource(DataSource dataSource)
    {
        this.dataSource = dataSource;
    }

    public void setAuditLoggingService(AuditLoggingService auditLoggingService)
    {
        this.auditLoggingService = auditLoggingService;
        certPublisher.setAuditLoggingService(auditLoggingService);
    }
}
