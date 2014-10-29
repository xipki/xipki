/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.common;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.crypto.RuntimeCryptoException;
import org.xipki.common.IoCertUtil;
import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class X509CertificateWithMetaInfo
{
    private Integer certId;
    private final X509Certificate cert;
    private final String subject;
    private final byte[] encodedCert;

    public X509CertificateWithMetaInfo(X509Certificate cert)
    {
        this(cert, null);
    }

    public X509CertificateWithMetaInfo(X509Certificate cert, byte[] encodedCert)
    {
        ParamChecker.assertNotNull("cert", cert);

        this.cert = cert;

        this.subject = IoCertUtil.canonicalizeName(cert.getSubjectX500Principal());

        if(encodedCert == null)
        {
            try
            {
                this.encodedCert = cert.getEncoded();
            } catch (CertificateEncodingException e)
            {
                throw new RuntimeCryptoException("could not encode certificate: " + e.getMessage());
            }
        }
        else
        {
            this.encodedCert = encodedCert;
        }
    }

    public X509Certificate getCert()
    {
        return cert;
    }

    public byte[] getEncodedCert()
    {
        return encodedCert;
    }

    public String getSubject()
    {
        return subject;
    }

    @Override
    public String toString()
    {
        return cert.toString();
    }

    public Integer getCertId()
    {
        return certId;
    }

    public void setCertId(Integer certId)
    {
        this.certId = certId;
    }

}
