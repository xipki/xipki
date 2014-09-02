/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.api;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CertProfileEntry implements Serializable
{
    private String name;
    private String type;
    private String conf;

    public CertProfileEntry(String name, String type, String conf)
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotEmpty("type", type);
        this.name = name;
        this.type = type;
        this.conf = conf;
        this.serialVersion = SERIAL_VERSION;
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

    // ------------------------------------------------
    // Customized serialization
    // ------------------------------------------------
    private static final long serialVersionUID = 1L;

    private static final String SR_serialVersion = "serialVersion";
    private static final double SERIAL_VERSION = 1.0;

    private static final String SR_name = "name";
    private static final String SR_type = "type";
    private static final String SR_conf = "conf";

    private double serialVersion;

    private void writeObject(java.io.ObjectOutputStream out)
    throws IOException
    {
        final Map<String, Object> serialMap = new HashMap<String, Object>();

        serialMap.put(SR_serialVersion, serialVersion);
        serialMap.put(SR_name, name);
        serialMap.put(SR_type, type);
        serialMap.put(SR_conf, conf);

        out.writeObject(serialMap);
    }

    @SuppressWarnings("unchecked")
    private void readObject(java.io.ObjectInputStream in)
    throws IOException, ClassNotFoundException
    {
        final Map<String, Object> serialMap = (Map<String, Object>) in.readObject();
        serialVersion = (double) serialMap.get(SR_serialVersion);

        name = (String) serialMap.get(SR_name);
        type = (String) serialMap.get(SR_type);
        conf = (String) serialMap.get(SR_conf);
    }
}
