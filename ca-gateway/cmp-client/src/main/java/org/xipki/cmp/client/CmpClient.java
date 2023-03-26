// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.cert.X509CRLHolder;
import org.xipki.security.X509Cert;
import org.xipki.util.ReqRespDebug;

import java.io.Closeable;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * CMP client interface.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public interface CmpClient extends Closeable {

  /**
   * Enrolls a certificate.
   *
   * @param caName
   *          CA name. Must not be {@code null}.
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
   * @throws CmpClientException
   *          if client error occurs.
   */
  EnrollCertResult enrollCert(
      String caName, Requestor requestor, CertificationRequest csr, String profile,
      Instant notBefore, Instant notAfter, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException;

  /**
   * Enrolls a set of certificates.
   *
   * @param caName
   *          CA name. Must not be {@code null}.
   * @param request
   *          Request. Must not be {@code null}.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return the enrolling result.
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CmpClientException
   *          if client error occurs.
   */
  EnrollCertResult enrollCerts(
      String caName, Requestor requestor, EnrollCertRequest request, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException;

  /**
   * Revokes a certificate.
   * @param caName
   *          CA name. Must not be {@code null}.
   * @param issuerCert
   *          Issuer's certificate. Must not be {@code null}.
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
   * @throws CmpClientException
   *          if client error occurs.
   */
  CertIdOrError revokeCert(
      String caName, Requestor requestor, X509Cert issuerCert, BigInteger serial,
      int reason, Instant invalidityTime, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException;

  /**
   * Revokes a certificate.
   *
   * @param caName
   *          CA name. Must not be {@code null}.
   * @param issuerCert
   *          Issuer's certificate. Must not be {@code null}.
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
   * @throws CmpClientException
   *          if client error occurs.
   */
  CertIdOrError revokeCert(
      String caName, Requestor requestor, X509Cert issuerCert, X509Cert cert,
      int reason, Instant invalidityTime, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException;

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
   * @throws CmpClientException
   *          if client error occurs.
   */
  Map<String, CertIdOrError> revokeCerts(
      String caName, Requestor requestor, RevokeCertRequest request, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException;

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
   * @throws CmpClientException
   *          if client error occurs.
   */
  X509CRLHolder downloadCrl(String caName, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException;

  /**
   * Unsuspends a certificate.
   * @param caName
   *          CA name. Must not be {@code null}.
   * @param issuerCert
   *          Issuer's certificate. Must not be {@code null}.
   * @param serial
   *          Serial number of the certificate. Must not be {@code null}.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return result of action.
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CmpClientException
   *          if client error occurs.
   */
  CertIdOrError unsuspendCert(
      String caName, Requestor requestor, X509Cert issuerCert, BigInteger serial, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException;

  /**
   * Unsuspends certificates.
   *
   * @param caName
   *          CA name. Must not be {@code null}.
   * @param issuerCert
   *          Issuer's certificate. Must not be {@code null}.
   * @param cert
   *          Target certificate. Must not be {@code null}.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return result of the unrevocation.
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CmpClientException
   *          if client error occurs.
   */
  CertIdOrError unsuspendCert(
      String caName, Requestor requestor, X509Cert issuerCert, X509Cert cert, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException;

  /**
   * Unsuspends certificates.
   *
   * @param caName
   *          CA name. Must not be {@code null}.
   * @param request
   *          Request. Must not be {@code null}.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return result of the unrevocation.
   * @throws PkiErrorException
   *          if the response returns none-success status.
   * @throws CmpClientException
   *          if client error occurs.
   */
  Map<String, CertIdOrError> unsuspendCerts(
      String caName, Requestor requestor, UnrevokeCertRequest request, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException;

  /**
   * Returns the CA certificate.
   * @param caName
   *          the CA name
   * @return the CA certificate
   * @throws CmpClientException
   *          if client error occurs.
   */
  X509Cert caCert(String caName, ReqRespDebug debug) throws CmpClientException, PkiErrorException;

  /**
   * Returns the CA certificate chain.
   * @param caName
   *          the CA name
   * @return the CA certificate
   * @throws CmpClientException
   *          if client error occurs.
   */
  List<X509Cert> caCerts(String caName, ReqRespDebug debug) throws CmpClientException, PkiErrorException;

  /**
   * Returns the certificates held by CA for the DH KeyAgreement.
   * @return the certificates held by CA for the DH KeyAgreement,
   * @throws CmpClientException
   *          if client error occurs.
   */
  List<X509Cert> getDhPopPeerCertificates() throws CmpClientException;

}
