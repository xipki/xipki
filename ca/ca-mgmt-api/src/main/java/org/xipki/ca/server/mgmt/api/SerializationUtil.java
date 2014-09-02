/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.api;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

class SerializationUtil
{

    static void writeCert(Map<String, Object> serialMap, String serialKey, X509Certificate cert)
    throws IOException
    {
        byte[] encodedCert = null;
        if(cert != null)
        {
            try
            {
                encodedCert = cert.getEncoded();
            } catch (CertificateEncodingException e)
            {
                throw new IOException("could not encode the cert: " + e.getMessage(), e);
            }
        }
        serialMap.put(serialKey, encodedCert);
    }

    static X509Certificate readCert(Map<String, Object> serialMap, String serialKey)
    throws IOException
    {
        byte[] encodedCert = (byte[]) serialMap.get(serialKey);
        if(encodedCert == null)
        {
            return null;
        }

        try
        {
            return IoCertUtil.parseCert(encodedCert);
        } catch (CertificateException e)
        {
            throw new IOException("could not parse certificate: " + e.getMessage(), e);
        }
    }

}
