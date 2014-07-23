/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.client.api;

import java.math.BigInteger;
import java.net.URL;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;

/**
 * @author Lijun Liao
 */

public interface OCSPRequestor
{
    public static final ASN1ObjectIdentifier id_pkix_ocsp_prefSigAlgs = OCSPObjectIdentifiers.id_pkix_ocsp.branch("8");
    public static final ASN1ObjectIdentifier id_pkix_ocsp_extendedRevoke = OCSPObjectIdentifiers.id_pkix_ocsp.branch("9");

    BasicOCSPResp ask(X509Certificate caCert, X509Certificate cert,
            URL responderUrl, RequestOptions requestOptions)
    throws OCSPRequestorException;

    BasicOCSPResp ask(X509Certificate caCert, BigInteger serialNumber,
            URL responderUrl, RequestOptions requestOptions)
    throws OCSPRequestorException;
}
