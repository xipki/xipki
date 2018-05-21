/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface CaClient {

  Set<String> getCaNames();

  /**
   * TODO.
   * @param caName
   *          CA name. Must not be {@code null}
   * @return the certificate profiles supported by the given CA.
   * @throws CaClientException
   *          if client error occurs.
   */
  Set<CertprofileInfo> getCertprofiles(String caName) throws CaClientException;

  /**
   * TODO.
   * Enrolls a certificate
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
   * @return the enrolling result.
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CaClientException
   *          if client error occurs.
   */
  EnrollCertResult requestCert(String caName, CertificationRequest csr, String profile,
      Date notBefore, Date notAfter, RequestResponseDebug debug)
      throws CaClientException, PkiErrorException;

  /**
   * Enrolls a set of certificates.
   *
   * @param caName
   *          CA name. Could be {@code null}.
   * @param request
   *          Request. Must not be {@code null}.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return the enrolling result.
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CaClientException
   *          if client error occurs.
   */
  EnrollCertResult requestCerts(String caName, EnrollCertRequest request,
      RequestResponseDebug debug) throws CaClientException, PkiErrorException;

  /**
   * Revokes a certificate.
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
   * @return the revocation result.
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CaClientException
   *          if client error occurs.
   */
  CertIdOrError revokeCert(String caName, BigInteger serial, int reason, Date invalidityTime,
      RequestResponseDebug debug) throws CaClientException, PkiErrorException;

  /**
   * TODO.
   * Revokes a certificate
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
   * @return the revocation result.
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CaClientException
   *          if client error occurs.
   */
  CertIdOrError revokeCert(String caName, X509Certificate cert, int reason, Date invalidityTime,
      RequestResponseDebug debug) throws CaClientException, PkiErrorException;

  /**
   * Revoke a set of certificates.
   *
   * @param request
   *          Request. Must not be {@code null}.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return the revocation result.
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CaClientException
   *          if client error occurs.
   */
  Map<String, CertIdOrError> revokeCerts(RevokeCertRequest request, RequestResponseDebug debug)
      throws CaClientException, PkiErrorException;

  /**
   * Downloads the current CRL.
   *
   * @param caName
   *          CA name. Must not be {@code null}.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return the X509 CRL. Must not be {@code null}.
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CaClientException
   *          if client error occurs.
   */
  X509CRL downloadCrl(String caName, RequestResponseDebug debug)
      throws CaClientException, PkiErrorException;

  /**
   * Downloads the CRL for the given CRL number.
   *
   * @param caName
   *          CA name. Must not be {@code null}.
   * @param crlNumber
   *          CRL number. {@code null} to download the current CRL.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return the X509 CRL. Must not be {@code null}.
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CaClientException
   *          if client error occurs.
   */
  X509CRL downloadCrl(String caName, BigInteger crlNumber, RequestResponseDebug debug)
      throws CaClientException, PkiErrorException;

  /**
   * Generates and downloads a new CRL.
   *
   * @param caName
   *          CA name. Must not be {@code null}.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return the X509 CRL. Must not be {@code null}.
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CaClientException
   *          if client error occurs.
   */
  X509CRL generateCrl(String caName, RequestResponseDebug debug)
      throws CaClientException, PkiErrorException;

  /**
   * Gets the name of the CA.
   * @param issuer
   *          Issuer's subject.
   * @return the CA name
   * @throws CaClientException
   *          if client error occurs.
   */
  String getCaNameByIssuer(X500Name issuer) throws CaClientException;

  /**
   * Creates the PKIMessage sent to CA and returns its encoded form.
   *
   * @param certRequest
   *          Core request to enroll certificate. Must not be {@code null}.
   * @param popo
   *          ProofOfPossession. Must not be {@code null}.
   * @param profileName
   *          Certificate profile name. Must not be {@code null}.
   * @param caName
   *          CA name. Could be {@code null}.
   * @return encoded PKIMessage
   * @throws CaClientException
   *          if client error occurs.
   */
  byte[] envelope(CertRequest certRequest, ProofOfPossession popo, String profileName,
      String caName) throws CaClientException;

  /**
   * Creates the PKIMessage sent to CA and returns its encoded form.
   *
   * @param issuer
   *          Issuer of the certificate. Must not be {@code null}.
   * @param serial
   *          Serial number of the certificate. Must not be {@code null}.
   * @param reason
   *          Revocation reason.
   * @return encoded PKIMessage
   * @throws CaClientException
   *          if client error occurs.
   */
  byte[] envelopeRevocation(X500Name issuer, BigInteger serial, int reason)
      throws CaClientException;

  /**
   * Creates the PKIMessage sent to CA and returns its encoded form.
   *
   * @param cert
   *          Certificate. Must not be {@code null}.
   * @param reason
   *          Revocation reason.
   * @return encoded PKIMessage
   * @throws CaClientException
   *          if client error occurs.
   */
  byte[] envelopeRevocation(X509Certificate cert, int reason) throws CaClientException;

  /**
   * Unrevokes a certificate.
   * @param caName
   *          CA name. Could be {@code null}.
   * @param serial
   *          Serial number of the certificate. Must not be {@code null}.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return result of the unrevocation.
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CaClientException
   *          if client error occurs.
   */
  CertIdOrError unrevokeCert(String caName, BigInteger serial, RequestResponseDebug debug)
            throws CaClientException, PkiErrorException;

  /**
   * Unrevokes certificates.
   *
   * @param caName
   *          CA name. Could be {@code null}.
   * @param cert
   *          Target certificate. Must not be {@code null}.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return result of the unrevocation.
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CaClientException
   *          if client error occurs.
   */
  CertIdOrError unrevokeCert(String caName, X509Certificate cert, RequestResponseDebug debug)
      throws CaClientException, PkiErrorException;

  /**
   * Unrevokes certificates.
   * @param request
   *          Request. Must not be {@code null}.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return result of the unrevocation.
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CaClientException
   *          if client error occurs.
   */
  Map<String, CertIdOrError> unrevokeCerts(UnrevokeOrRemoveCertRequest request,
      RequestResponseDebug debug) throws CaClientException, PkiErrorException;

  /**
   * Removes a certificate.
   *
   * @param caName
   *          CA name. Could be {@code null}.
   * @param serial
   *          Serial number of the target certificate.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return the result of the remove
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CaClientException
   *          if client error occurs.
   */
  CertIdOrError removeCert(String caName, BigInteger serial, RequestResponseDebug debug)
      throws CaClientException, PkiErrorException;

  /**
   * Removes a certificate.
   *
   * @param caName
   *          CA name. Could be {@code null}.
   * @param cert
   *          Target certificate.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return result of the removing
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CaClientException
   *          if client error occurs.
   */
  CertIdOrError removeCert(String caName, X509Certificate cert,
      RequestResponseDebug debug) throws CaClientException, PkiErrorException;

  /**
   * Removes certificates.
   * @param request
   *          Request. Must not be {@code null}.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return the result of the removing
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CaClientException
   *          if client error occurs.
   */
  Map<String, CertIdOrError> removeCerts(UnrevokeOrRemoveCertRequest request,
      RequestResponseDebug debug) throws CaClientException, PkiErrorException;

  /**
   * Gets the health status.
   * @param caName
   *          CA name. Must not be {@code null}.
   * @return the health status.
   * @throws CaClientException
   *          if client error occurs.
   */
  HealthCheckResult getHealthCheckResult(String caName) throws CaClientException;

  /**
   * Returns the CA certificate.
   * @param caName
   *          the CA name
   * @return the CA certificate
   * @throws CaClientException
   *          if client error occurs.
   */
  Certificate getCaCert(String caName) throws CaClientException;

}
