/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.api;

import java.util.HashMap;
import java.util.Map;

import org.xipki.audit.api.AuditLoggingServiceRegister;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class PublisherEntry
{
    private static final Map<String, IdentifiedCertPublisher> publisherPool = new HashMap<>();

    private final String name;
    private String type;
    private String conf;

    private PasswordResolver passwordResolver;
    private DataSourceWrapper dataSource;
    private IdentifiedCertPublisher certPublisher;
    private AuditLoggingServiceRegister auditServiceRegister;

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

        String _type = "ocsp".equalsIgnoreCase(type) ? "java:org.xipki.ca.server.publisher.DefaultCertPublisher" : type;

        CertPublisher realPublisher;
        if(_type.toLowerCase().startsWith("java:"))
        {
            String className = _type.substring("java:".length());
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
        this.certPublisher.setAuditServiceRegister(auditServiceRegister);

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

    public DataSourceWrapper getDataSource()
    {
        return dataSource;
    }

    public void setDataSource(DataSourceWrapper dataSource)
    {
        this.dataSource = dataSource;
    }

    public void setAuditServiceRegister(AuditLoggingServiceRegister serviceRegister)
    {
        this.auditServiceRegister = serviceRegister;
        certPublisher.setAuditServiceRegister(serviceRegister);
    }
}
