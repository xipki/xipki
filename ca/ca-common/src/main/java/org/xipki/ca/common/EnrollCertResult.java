/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.common;

import java.security.cert.Certificate;
import java.util.Map;
import java.util.Set;

/**
 * @author Lijun Liao
 */

public class EnrollCertResult
{

    private final Certificate caCertificate;
    private final Map<String, CertificateOrError> certificatesOrErrors;

    public EnrollCertResult(Certificate caCertificate,
            Map<String, CertificateOrError> certificatesOrErrors)
    {
        this.caCertificate = caCertificate;
        this.certificatesOrErrors = certificatesOrErrors;
    }

    public Certificate getCaCertificate()
    {
        return caCertificate;
    }

    public CertificateOrError getCertificateOrError(String id)
    {
        return certificatesOrErrors.get(id);
    }

    public Set<String> getAllIds()
    {
        return certificatesOrErrors.keySet();
    }

}
