/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.api;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.cmp.client.type.EnrollCertEntryType;
import org.xipki.ca.cmp.client.type.EnrollCertRequestType;
import org.xipki.ca.cmp.client.type.RevokeCertRequestType;
import org.xipki.ca.cmp.client.type.UnrevokeOrRemoveCertRequestType;
import org.xipki.ca.common.CertIDOrError;
import org.xipki.ca.common.EnrollCertResult;
import org.xipki.ca.common.PKIErrorException;
import org.xipki.ca.common.RAWorkerException;

/**
 * @author Lijun Liao
 */

public interface RAWorker
{
    Set<String> getCaNames();

    EnrollCertResult requestCert(CertificationRequest p10Request, String profile, String caName,
            String username)
    throws RAWorkerException, PKIErrorException;

    EnrollCertResult requestCerts(EnrollCertRequestType.Type type,
            Map<String, EnrollCertEntryType> enrollCertEntries, String caName, String username)
    throws RAWorkerException, PKIErrorException;

    EnrollCertResult requestCerts(EnrollCertRequestType request, String caName, String username)
    throws RAWorkerException, PKIErrorException;

    CertIDOrError revokeCert(X500Name issuer, BigInteger serial, int reason)
    throws RAWorkerException, PKIErrorException;

    CertIDOrError revokeCert(X509Certificate cert, int reason)
    throws RAWorkerException, PKIErrorException;

    Map<String, CertIDOrError> revokeCerts(RevokeCertRequestType request)
    throws RAWorkerException, PKIErrorException;

    X509CRL downloadCRL(String caName)
    throws RAWorkerException, PKIErrorException;

    X509CRL generateCRL(String caName)
    throws RAWorkerException, PKIErrorException;

    String getCaNameByIssuer(X500Name issuer)
    throws RAWorkerException;

    byte[] envelope(CertRequest certRequest, ProofOfPossession popo, String profileName,
            String caName, String username)
    throws RAWorkerException;

    byte[] envelopeRevocation(X500Name issuer, BigInteger serial, int reason)
    throws RAWorkerException;

    byte[] envelopeRevocation(X509Certificate cert, int reason)
    throws RAWorkerException;

    CertIDOrError unrevokeCert(X500Name issuer, BigInteger serial)
    throws RAWorkerException, PKIErrorException;

    CertIDOrError unrevokeCert(X509Certificate cert)
    throws RAWorkerException, PKIErrorException;

    Map<String, CertIDOrError> unrevokeCerts(UnrevokeOrRemoveCertRequestType request)
    throws RAWorkerException, PKIErrorException;

    CertIDOrError removeCert(X500Name issuer, BigInteger serial)
    throws RAWorkerException, PKIErrorException;

    CertIDOrError removeCert(X509Certificate cert)
    throws RAWorkerException, PKIErrorException;

    Map<String, CertIDOrError> removeCerts(UnrevokeOrRemoveCertRequestType request)
    throws RAWorkerException, PKIErrorException;

}
