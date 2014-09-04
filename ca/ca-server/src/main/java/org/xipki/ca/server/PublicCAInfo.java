/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/**
 * @author Lijun Liao
 */

public class PublicCAInfo
{
    private final X509Certificate caCertificate;
    private X509Certificate crlSignerCertificate;
    private final List<String> ocspUris;
    private final List<String> crlUris;
    private final List<String> caIssuerLocations;
    private final List<String> deltaCrlUris;

    public PublicCAInfo(X509Certificate caCertificate,
            List<String> ocspUris, List<String> crlUris,
            List<String> caIssuerLocations, List<String> deltaCrlUris)
    {
        this.caCertificate = caCertificate;
        this.ocspUris = ocspUris;
        this.crlUris = crlUris;
        this.caIssuerLocations = caIssuerLocations;
        this.deltaCrlUris = deltaCrlUris;
    }

    public X509Certificate getCACertificate()
    {
        return caCertificate;
    }

    public List<String> getOcspUris()
    {
        return ocspUris == null ? null : Collections.unmodifiableList(ocspUris);
    }

    public List<String> getCrlUris()
    {
        return crlUris == null ? null : Collections.unmodifiableList(crlUris);
    }

    public List<String> getCaIssuerLocations()
    {
        return caIssuerLocations == null ? null : Collections.unmodifiableList(caIssuerLocations);
    }

    public List<String> getDeltaCrlUris()
    {
        return deltaCrlUris == null ? null : Collections.unmodifiableList(deltaCrlUris);
    }

    public X509Certificate getCrlSignerCertificate()
    {
        return crlSignerCertificate;
    }

    public void setCrlSignerCertificate(X509Certificate crlSignerCert)
    {
        if(caCertificate.equals(crlSignerCert))
        {
            this.crlSignerCertificate = null;
        }
        else
        {
            this.crlSignerCertificate = crlSignerCert;
        }
    }
}
