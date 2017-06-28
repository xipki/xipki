/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.client.api;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.common.HealthCheckResult;
import org.xipki.common.RequestResponseDebug;
import org.xipki.pki.ca.client.api.dto.EnrollCertRequest;
import org.xipki.pki.ca.client.api.dto.RevokeCertRequest;
import org.xipki.pki.ca.client.api.dto.UnrevokeOrRemoveCertRequest;

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

}
