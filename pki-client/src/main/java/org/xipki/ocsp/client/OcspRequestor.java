// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.client;

import org.bouncycastle.cert.ocsp.OCSPResp;
import org.xipki.security.pkix.X509Cert;
import org.xipki.util.extra.misc.ReqRespDebug;

import java.math.BigInteger;
import java.net.URL;

/**
 * OCSP requestor interface.
 *
 * @author Lijun Liao (xipki)
 */

public interface OcspRequestor {

  /**
   * Asks for the status of the given certificate.
   *
   * @param issuerCert
   *          Issuer certificate. Must not be {@code null}.
   * @param cert
   *          Target certificate. Must not be {@code null}.
   * @param responderUrl
   *          Responder URL. Must not be {@code null}.
   * @param requestOptions
   *          Request options. Must not be {@code null}.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return the OCSP response.
   * @throws OcspRequestorException
   *         if cannot build the OCSP request
   * @throws OcspResponseException
   *         if the OCSP responder cannot be reached or the response does not
   *         match the requested certificate.
   */
  OCSPResp ask(X509Cert issuerCert, X509Cert cert, URL responderUrl,
               RequestOptions requestOptions, ReqRespDebug debug)
      throws OcspResponseException, OcspRequestorException;

  /**
   * Asks for the status of the given certificate.
   *
   * @param issuerCert
   *          Issuer certificate. Must not be {@code null}.
   * @param certs
   *          Target certificates. Must not be {@code null}.
   * @param responderUrl
   *          Responder URL. Must not be {@code null}.
   * @param requestOptions
   *          Request options. Must not be {@code null}.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return the OCSP response.
   * @throws OcspRequestorException
   *         if cannot build the OCSP request
   * @throws OcspResponseException
   *         if the OCSP responder cannot be reached or the response does not
   *         match the requested certificate.
   */
  OCSPResp ask(X509Cert issuerCert, X509Cert[] certs, URL responderUrl,
               RequestOptions requestOptions, ReqRespDebug debug)
      throws OcspResponseException, OcspRequestorException;

  /**
   * Asks for the status of the given certificate.
   *
   * @param issuerCert
   *          Issuer certificate. Must not be {@code null}.
   * @param serialNumber
   *          Serial number of the target certificate. Must not be {@code null}.
   * @param responderUrl
   *          Responder URL. Must not be {@code null}.
   * @param requestOptions
   *          Request options. Must not be {@code null}.
   * @param debug
   *          Request/response debug control. Could be {@code null}.
   * @return the OCSP response.
   * @throws OcspRequestorException
   *         if cannot build the OCSP request
   * @throws OcspResponseException
   *         if the OCSP responder cannot be reached or the response does not
   *         match the requested certificate.
   */
  OCSPResp ask(X509Cert issuerCert, BigInteger serialNumber, URL responderUrl,
               RequestOptions requestOptions, ReqRespDebug debug)
      throws OcspResponseException, OcspRequestorException;

  /**
   * Asks for the status of the given certificates.
   *
   * @param issuerCert
   *        Issuer certificate. Must not be {@code null}.
   * @param serialNumbers
   *        Serial numbers of the target certificates. Must not be {@code null}.
   * @param responderUrl
   *        Responder URL. Must not be {@code null}.
   * @param requestOptions
   *        Request options. Must not be {@code null}.
   * @param debug
   *        Request/response debug control. Could be {@code null}.
   * @return the OCSP response.
   * @throws OcspRequestorException
   *         if cannot build the OCSP request
   * @throws OcspResponseException
   *         if the OCSP responder cannot be reached or the response does not
   *         match the requested certificates.
   */
  OCSPResp ask(X509Cert issuerCert, BigInteger[] serialNumbers,
               URL responderUrl, RequestOptions requestOptions,
               ReqRespDebug debug)
      throws OcspResponseException, OcspRequestorException;

}
