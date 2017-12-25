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

package org.xipki.ocsp.client.api;

import java.math.BigInteger;
import java.net.URL;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.ocsp.OCSPResp;
import org.xipki.common.RequestResponseDebug;

/**
 * @author Lijun Liao
 * @since 2.0.0
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
     *         if the OCSP responder cannot be reached or the response does not match the requested
     *         certificate.
     */
    OCSPResp ask(X509Certificate issuerCert, X509Certificate cert,
            URL responderUrl, RequestOptions requestOptions,
            RequestResponseDebug debug)
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
     *         if the OCSP responder cannot be reached or the response does not match the requested
     *         certificate.
     */
    OCSPResp ask(X509Certificate issuerCert, X509Certificate[] certs,
            URL responderUrl, RequestOptions requestOptions,
            RequestResponseDebug debug)
            throws OcspResponseException, OcspRequestorException;

    /**
     *
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
     *         if the OCSP responder cannot be reached or the response does not match the requested
     *         certificate.
     */
    OCSPResp ask(X509Certificate issuerCert, BigInteger serialNumber,
            URL responderUrl, RequestOptions requestOptions,
            RequestResponseDebug debug)
            throws OcspResponseException, OcspRequestorException;

    /**
     * Asks for the status of the given certificates.
     *
     * @param issuerCert
     *          Issuer certificate. Must not be {@code null}.
     * @param serialNumbers
     *          Serial numbers of the target certificates. Must not be {@code null}.
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
     *         if the OCSP responder cannot be reached or the response does not match the requested
     *         certificates.
     */
    OCSPResp ask(X509Certificate issuerCert, BigInteger[] serialNumbers,
            URL responderUrl, RequestOptions requestOptions,
            RequestResponseDebug debug)
            throws OcspResponseException, OcspRequestorException;

}
