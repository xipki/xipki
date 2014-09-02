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
import org.xipki.security.common.ConfigurationException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CrlSignerEntry implements Serializable
{
    private String name;
    private String signerType;
    private String signerConf;
    private X509Certificate cert;

    private CRLControl crlControl;

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
        this.serialVersion = SERIAL_VERSION;
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
            sb.append("cert: not set\n");
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
    private static final String SR_signerType = "signerType";
    private static final String SR_signerConf = "signerConf";
    private static final String SR_cert = "cert";
    private static final String SR_crlControl = "crlControl";

    private double serialVersion;

    private void writeObject(java.io.ObjectOutputStream out)
    throws IOException
    {
        final Map<String, Object> serialMap = new HashMap<String, Object>();

        serialMap.put(SR_serialVersion, serialVersion);
        serialMap.put(SR_name, name);
        serialMap.put(SR_signerType, signerType);
        serialMap.put(SR_signerConf, signerConf);
        SerializationUtil.writeCert(serialMap, SR_cert, cert);
        serialMap.put(SR_crlControl, crlControl == null ? null : crlControl.getConf());

        out.writeObject(serialMap);
    }

    @SuppressWarnings("unchecked")
    private void readObject(java.io.ObjectInputStream in)
    throws IOException, ClassNotFoundException
    {
        final Map<String, Object> serialMap = (Map<String, Object>) in.readObject();
        serialVersion = (double) serialMap.get(SR_serialVersion);

        name = (String) serialMap.get(SR_name);
        signerType = (String) serialMap.get(SR_signerType);
        signerConf = (String) serialMap.get(SR_signerConf);
        cert = SerializationUtil.readCert(serialMap, SR_cert);
        String s = (String) serialMap.get(SR_crlControl);
        if(s == null)
        {
            crlControl = null;
        }
        else
        {
            try
            {
                crlControl = CRLControl.getInstance(s);
            } catch (ConfigurationException e)
            {
                throw new IOException("Could not reconstruct CRLControl: " + e.getMessage(), e);
            }
        }
    }
}
