/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.api;

import java.io.IOException;
import java.io.Serializable;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CmpRequestorEntry implements Serializable
{
    private String name;
    private X509Certificate cert;

    public CmpRequestorEntry(String name)
    {
        ParamChecker.assertNotEmpty("name", name);
        this.name = name;
        this.serialVersion = SERIAL_VERSION;
    }

    public String getName()
    {
        return name;
    }

    public X509Certificate getCert()
    {
        return cert;
    }

    public void setCert(X509Certificate cert)
    {
        this.cert = cert;
    }

    @Override
    public String toString()
    {
        return toString(false);
    }

    public String toString(boolean verbose)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("name: ").append(name).append('\n');
        if(cert != null)
        {
            sb.append("cert: ").append("\n");
            sb.append("\tissuer: ").append(
                    IoCertUtil.canonicalizeName(cert.getIssuerX500Principal())).append("\n");
            sb.append("\tserialNumber: ").append(cert.getSerialNumber()).append("\n");
            sb.append("\tsubject: ").append(
                    IoCertUtil.canonicalizeName(cert.getSubjectX500Principal())).append('\n');
            if(verbose)
            {
                sb.append("\tencoded: ");
                try
                {
                    sb.append(Base64.toBase64String(cert.getEncoded()));
                } catch (CertificateEncodingException e)
                {
                    sb.append("ERROR");
                }
            }
        }
        else
        {
            sb.append("cert: not set");
        }

        return sb.toString();
    }

    // ------------------------------------------------
    // Customized serialization
    // ------------------------------------------------
    private static final long serialVersionUID = 1L;

    private static final String SR_serialVersion = "serialVersion";
    private static final double SERIAL_VERSION = 1.0;

    private static final String SR_name = "name";
    private static final String SR_cert = "cert";

    private double serialVersion;

    private void writeObject(java.io.ObjectOutputStream out)
    throws IOException
    {
        final Map<String, Object> serialMap = new HashMap<String, Object>();

        serialMap.put(SR_serialVersion, serialVersion);
        serialMap.put(SR_name, name);
        SerializationUtil.writeCert(serialMap, SR_cert, cert);

        out.writeObject(serialMap);
    }

    @SuppressWarnings("unchecked")
    private void readObject(java.io.ObjectInputStream in)
    throws IOException, ClassNotFoundException
    {
        final Map<String, Object> serialMap = (Map<String, Object>) in.readObject();
        serialVersion = (double) serialMap.get(SR_serialVersion);

        name = (String) serialMap.get(SR_name);
        cert = SerializationUtil.readCert(serialMap, SR_cert);
    }
}
