/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt;

import java.util.HashMap;
import java.util.Map;

import org.xipki.audit.api.AuditLoggingServiceRegister;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.common.CertPublisherException;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.publisher.DefaultCertPublisher;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.CmpUtf8Pairs;
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
        if("ocsp".equalsIgnoreCase(type))
        {
            realPublisher = new DefaultCertPublisher();
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
        CmpUtf8Pairs confPairs = null;
        try
        {
            confPairs = new CmpUtf8Pairs(conf);
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
