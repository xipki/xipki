/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.api;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.security.common.ConfigurationException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CrlSignerEntry
{
    private final String name;
    private final String signerType;
    private final String signerConf;
    private X509Certificate cert;

    private final CRLControl crlControl;

    public CrlSignerEntry(String name, String signerType, String signerConf, String crlControlConf)
    throws ConfigurationException
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotEmpty("type", signerType);
        ParamChecker.assertNotEmpty("crlControlConf", crlControlConf);

        this.name = name;
        this.signerType = signerType;
        this.signerConf = signerConf;
        this.crlControl = CRLControl.getInstance(crlControlConf);
    }

    public String getName()
    {
        return name;
    }

    public String getType()
    {
        return signerType;
    }

    public String getConf()
    {
        return signerConf;
    }

    public X509Certificate getCertificate()
    {
        return cert;
    }

    public void setCertificate(X509Certificate cert)
    {
        this.cert = cert;
    }

    public CRLControl getCRLControl()
    {
        return crlControl;
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
        sb.append("signerType: ").append(signerType).append('\n');
        sb.append("signerConf: ").append(signerConf).append('\n');
        sb.append("crlControl: ").append(crlControl.getConf()).append("\n");
        if(cert != null)
        {
            sb.append("cert: ").append("\n");
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
            sb.append("cert: null\n");
        }

        return sb.toString();
    }

}
