/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.api;

import java.io.Serializable;

import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class PublisherEntry implements Serializable
{
    private static final long serialVersionUID = 1L;
    private final String name;
    private final String type;
    private final String conf;

    public PublisherEntry(String name, String type, String conf)
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotEmpty("type", type);
        this.name = name;
        this.type = type;
        this.conf = conf;
    }

    public String getName()
    {
        return name;
    }

    public String getType()
    {
        return type;
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

}
