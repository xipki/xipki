/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.client.api;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.client.api.dto.EnrollCertRequest;
import org.xipki.ca.client.api.dto.RevokeCertRequest;
import org.xipki.ca.client.api.dto.UnrevokeOrRemoveCertRequest;
import org.xipki.common.HealthCheckResult;
import org.xipki.common.RequestResponseDebug;
import org.xipki.security.X509Cert;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface CaClient {

    Set<String> caNames();

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}
     * @return
     * @throws CaClientException
     */
    Set<CertprofileInfo> getCertprofiles(String caName) throws CaClientException;

    /**
     *
     * @param caName
     *          CA name. Could be {@code null}.
     * @param csr
     *          CSR. Must not be{@code null}.
     * @param profile
     *          Certificate profile name. Must not be{@code null}.
     * @param notBefore
     *          NotBefore. Could be {@code null}.
     * @param notAfter
     *          NotAfter. Could be {@code null}.
     * @param debug
     *          Request/response debug control. Could be {@code null}.
     */
    EnrollCertResult requestCert(String caName, CertificationRequest csr,
            String profile, Date notBefore, Date notAfter, RequestResponseDebug debug)
            throws CaClientException, PkiErrorException;

    /**
     *
     * @param caName
     *          CA name. Could be {@code null}.
     * @param request
     *          Request. Must not be {@code null}.
     * @param debug
     *          Request/response debug control. Could be {@code null}.
     */
    EnrollCertResult requestCerts(String caName, EnrollCertRequest request,
            RequestResponseDebug debug)
            throws CaClientException, PkiErrorException;

    /**
     *
     * @param caName
     *          CA name. Could be {@code null}.
     * @param serial
     *          Serial number of the target certificate. Must not be {@code null}.
     * @param reason
     *          Revocation reason.
     * @param invalidityTime
     *          Invalidity time. Could be {@code null}.
     * @param debug
     *          Request/response debug control. Could be {@code null}.
     */
    CertIdOrError revokeCert(String caName, BigInteger serial, int reason,
            Date invalidityTime, RequestResponseDebug debug)
            throws CaClientException, PkiErrorException;

    /**
     *
     * @param caName
     *          CA name. Could be {@code null}.
     * @param cert
     *          Target certificate. Must not be {@code null}.
     * @param reason
     *          Revocation reason.
     * @param invalidityTime
     *          Invalidity time. Could be {@code null}.
     * @param debug
     *          Request/response debug control. Could be {@code null}.
     */
    CertIdOrError revokeCert(String caName, X509Certificate cert, int reason,
            Date invalidityTime, RequestResponseDebug debug)
            throws CaClientException, PkiErrorException;

    /**
     *
     * @param request
     *          Request. Must not be {@code null}.
     * @param debug
     *          Request/response debug control. Could be {@code null}.
     */
    Map<String, CertIdOrError> revokeCerts(RevokeCertRequest request,
            RequestResponseDebug debug) throws CaClientException, PkiErrorException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param debug
     *          Request/response debug control. Could be {@code null}.
     */
    X509CRL downloadCrl(String caName, RequestResponseDebug debug)
            throws CaClientException, PkiErrorException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param crlNumber
     *          CRL number. {@code null} to download the current CRL.
     * @param debug
     *          Request/response debug control. Could be {@code null}.
     */
    X509CRL downloadCrl(String caName, BigInteger crlNumber,
            RequestResponseDebug debug) throws CaClientException, PkiErrorException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param debug
     *          Request/response debug control. Could be {@code null}.
     */
    X509CRL generateCrl(String caName, RequestResponseDebug debug)
            throws CaClientException, PkiErrorException;

    /**
     *
     * @param issuer
     *          Issuer's subject.
     */
    String getCaNameByIssuer(X500Name issuer) throws CaClientException;

    /**
     *
     * @param certRequest
     *          Core request to enroll certificate. Must not be {@code null}.
     * @param popo
     *          ProofOfPossession. Must not be {@code null}.
     * @param profileName
     *          Certificate profile name. Must not be {@code null}.
     * @param caName
     *          CA name. Could be {@code null}.
     */
    byte[] envelope(CertRequest certRequest, ProofOfPossession popo,
            String profileName, String caName)
            throws CaClientException;

    /**
     *
     * @param issuer
     *          Issuer of the certificate. Must not be {@code null}.
     * @param serial
     *          Serial number of the certificate. Must not be {@code null}.
     * @param reason
     *          Revocation reason.
     */
    byte[] envelopeRevocation(X500Name issuer, BigInteger serial, int reason)
            throws CaClientException;

    /**
     *
     * @param cert
     *          Certificate. Must not be {@code null}.
     * @param reason
     *          Revocation reason.
     */
    byte[] envelopeRevocation(X509Certificate cert, int reason) throws CaClientException;

    /**
     *
     * @param caName
     *          CA name. Could be {@code null}.
     * @param serial
     *          Serial number of the certificate. Must not be {@code null}.
     * @param debug
     *          Request/response debug control. Could be {@code null}.
     */
    CertIdOrError unrevokeCert(String caName, BigInteger serial,
            RequestResponseDebug debug) throws CaClientException, PkiErrorException;

    /**
     *
     * @param caName
     *          CA name. Could be {@code null}.
     * @param cert
     *          Target certificate. Must not be {@code null}.
     * @param debug
     *          Request/response debug control. Could be {@code null}.
     */
    CertIdOrError unrevokeCert(String caName, X509Certificate cert,
            RequestResponseDebug debug) throws CaClientException, PkiErrorException;

    /**
     *
     * @param request
     *          Request. Must not be {@code null}.
     * @param debug
     *          Request/response debug control. Could be {@code null}.
     */
    Map<String, CertIdOrError> unrevokeCerts(UnrevokeOrRemoveCertRequest request,
            RequestResponseDebug debug) throws CaClientException, PkiErrorException;

    /**
     *
     * @param caName
     *          CA name. Could be {@code null}.
     * @param serial
     *          Serial number of the target certificate.
     * @param debug
     *          Request/response debug control. Could be {@code null}.
     */
    CertIdOrError removeCert(String caName, BigInteger serial, RequestResponseDebug debug)
            throws CaClientException, PkiErrorException;

    /**
     *
     * @param caName
     *          CA name. Could be {@code null}.
     * @param cert
     *          Target certificate.
     * @param debug
     *          Request/response debug control. Could be {@code null}.
     */
    CertIdOrError removeCert(String caName, X509Certificate cert,
            RequestResponseDebug debug) throws CaClientException, PkiErrorException;

    /**
     *
     * @param request
     *          Request. Must not be {@code null}.
     * @param debug
     *          Request/response debug control. Could be {@code null}.
     */
    Map<String, CertIdOrError> removeCerts(UnrevokeOrRemoveCertRequest request,
            RequestResponseDebug debug)
            throws CaClientException, PkiErrorException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    HealthCheckResult getHealthCheckResult(String caName) throws CaClientException;

    /**
     *
     * @param caName
     * @return the CA certificate
     * @throws CaClientException
     */
    Certificate getCaCert(String caName) throws CaClientException;

}
