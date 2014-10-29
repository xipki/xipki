/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.api;

import java.io.Serializable;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

public class CmpResponderEntry implements Serializable
{
    private static final long serialVersionUID = 1L;
    public static final String name = "default";
    private String type;
    private String conf;
    private X509Certificate cert;

    public CmpResponderEntry()
    {
    }

    public String getType()
    {
        return type;
    }

    public void setType(String type)
    {
        this.type = type;
    }

    public String getConf()
    {
        return conf;
    }

    public void setConf(String conf)
    {
        this.conf = conf;
    }

    public X509Certificate getCertificate()
    {
        return cert;
    }

    public void setCertificate(X509Certificate cert)
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
        sb.append("type: ").append(type).append('\n');
        sb.append("conf: ");
        if(conf == null)
        {
            sb.append("null");
        }
        else if(verbose || conf.length() < 101)
        {
            sb.append(conf);
        }
        else
        {
            sb.append(conf.substring(0, 97)).append("...");
        }
        sb.append('\n');
        sb.append("cert: ").append("\n");
        if(cert != null)
        {
            sb.append("\tissuer: ").append(
                    IoCertUtil.canonicalizeName(cert.getIssuerX500Principal())).append('\n');
            sb.append("\tserialNumber: ").append(cert.getSerialNumber()).append('\n');
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
            sb.append("null");
        }
        return sb.toString();
    }

}
