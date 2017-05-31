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

package org.xipki.pki.ocsp.qa.benchmark;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentProvider;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.client.util.InputStreamContentProvider;
import org.eclipse.jetty.http.HttpMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.HashAlgoType;
import org.xipki.commons.security.ObjectIdentifiers;
import org.xipki.pki.ocsp.client.api.OcspRequestorException;
import org.xipki.pki.ocsp.client.api.OcspResponseException;
import org.xipki.pki.ocsp.client.api.RequestOptions;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

class OcspBenchmark {

    // result in maximal 254 Base-64 encoded octets
    public static final int MAX_LEN_GET = 190;

    public static final String CT_REQUEST = "application/ocsp-request";

    public static final String CT_RESPONSE = "application/ocsp-response";

    private static final Logger LOG = LoggerFactory.getLogger(OcspBenchmark.class);

    private final Extension[] extnType = new Extension[0];

    private final SecureRandom random = new SecureRandom();

    private AlgorithmIdentifier issuerhashAlg;

    private ASN1OctetString issuerNameHash;

    private ASN1OctetString issuerKeyHash;

    private Extension[] extensions;

    private RequestOptions requestOptions;

    private URI responderUrl;

    private HttpClient httpClient;

    private OcspResponseHandler responseHandler;

    public void init(final OcspResponseHandler responseHandler, final URI responderUrl,
            final Certificate issuerCert, final RequestOptions requestOptions)
            throws Exception {
        ParamUtil.requireNonNull("issuerCert", issuerCert);
        this.requestOptions = ParamUtil.requireNonNull("requestOptions", requestOptions);
        this.responderUrl = ParamUtil.requireNonNull("responderUrl", responderUrl);
        this.responseHandler = ParamUtil.requireNonNull("responseHandler", responseHandler);

        HashAlgoType hashAlgo = HashAlgoType.getHashAlgoType(requestOptions.getHashAlgorithmId());
        if (hashAlgo == null) {
            throw new OcspRequestorException("unknown HashAlgo "
                    + requestOptions.getHashAlgorithmId().getId());
        }

        this.issuerhashAlg = hashAlgo.getAlgorithmIdentifier();
        this.issuerNameHash = new DEROctetString(hashAlgo.hash(
                        issuerCert.getSubject().getEncoded()));
        this.issuerKeyHash = new DEROctetString(hashAlgo.hash(
                        issuerCert.getSubjectPublicKeyInfo().getPublicKeyData().getOctets()));

        List<AlgorithmIdentifier> prefSigAlgs = requestOptions.getPreferredSignatureAlgorithms();
        if (prefSigAlgs == null || prefSigAlgs.size() == 0) {
            this.extensions = null;
        } else {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            for (AlgorithmIdentifier algId : prefSigAlgs) {
                ASN1Sequence prefSigAlgObj = new DERSequence(algId);
                vec.add(prefSigAlgObj);
            }

            ASN1Sequence extnValue = new DERSequence(vec);
            Extension extn;
            try {
                extn = new Extension(ObjectIdentifiers.id_pkix_ocsp_prefSigAlgs, false,
                        new DEROctetString(extnValue));
            } catch (IOException ex) {
                throw new OcspRequestorException(ex.getMessage(), ex);
            }

            this.extensions = new Extension[]{extn};
        }

        this.httpClient = new HttpClient();
        this.httpClient.setFollowRedirects(false);
        this.httpClient.start();
    }

    public void stop() throws Exception {
        try {
            responseHandler.waitForFinish(10, TimeUnit.SECONDS);
        } catch (InterruptedException ex) {
            LOG.warn("got InterruptedException in waitForFinish");
        }

        httpClient.stop();
    }

    public void ask(final BigInteger[] serialNumbers)
            throws OcspResponseException, OcspRequestorException {
        try {
            responseHandler.waitForResource();
        } catch (InterruptedException ex) {
            throw new OcspRequestorException("could not get connection: " + ex.getMessage(), ex);
        }

        OCSPReq ocspReq = buildRequest(serialNumbers);
        byte[] encodedReq;
        try {
            encodedReq = ocspReq.getEncoded();
        } catch (IOException ex) {
            throw new OcspRequestorException("could not encode OCSP request: " + ex.getMessage(),
                    ex);
        }

        int size = encodedReq.length;

        Request request;

        if (size <= MAX_LEN_GET && requestOptions.isUseHttpGetForRequest()) {
            String b64Request = Base64.toBase64String(encodedReq);
            String urlEncodedReq;
            try {
                urlEncodedReq = URLEncoder.encode(b64Request, "UTF-8");
            } catch (UnsupportedEncodingException ex) {
                throw new OcspRequestorException(ex.getMessage());
            }
            StringBuilder urlBuilder = new StringBuilder();
            String baseUrl = responderUrl.toString();
            urlBuilder.append(baseUrl);
            if (!baseUrl.endsWith("/")) {
                urlBuilder.append('/');
            }
            urlBuilder.append(urlEncodedReq);
            String url = urlBuilder.toString();
            request = httpClient.newRequest(url)
                    .method(HttpMethod.GET)
                    .header("Content-Type", CT_REQUEST);
        } else {
            ContentProvider contentProvider = new InputStreamContentProvider(
                    new ByteArrayInputStream(encodedReq));
            request = httpClient.newRequest(responderUrl)
                    .method(HttpMethod.POST)
                    .content(contentProvider, CT_REQUEST);
        }

        OcspResponseContentListener contentListener = new OcspResponseContentListener();
        responseHandler.incrementNumPendingRequests();
        request.onResponseContent(contentListener);
        request.send(new OcspResponseCompleter(responseHandler, contentListener));
    } // method ask

    private OCSPReq buildRequest(final BigInteger[] serialNumbers)
            throws OcspRequestorException {
        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();

        if (requestOptions.isUseNonce() || extensions != null) {
            List<Extension> extns = new ArrayList<>(2);
            if (requestOptions.isUseNonce()) {
                Extension extn = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                        new DEROctetString(nextNonce(requestOptions.getNonceLen())));
                extns.add(extn);
            }

            if (extensions != null) {
                for (Extension extn : extensions) {
                    extns.add(extn);
                }
            }
            reqBuilder.setRequestExtensions(new Extensions(extns.toArray(extnType)));
        }

        try {
            for (BigInteger serialNumber : serialNumbers) {
                CertID certId = new CertID(issuerhashAlg, issuerNameHash, issuerKeyHash,
                        new ASN1Integer(serialNumber));
                reqBuilder.addRequest(new CertificateID(certId));
            }

            return reqBuilder.build();
        } catch (OCSPException ex) {
            throw new OcspRequestorException(ex.getMessage(), ex);
        }
    } // method buildRequest

    private byte[] nextNonce(final int nonceLen) {
        byte[] nonce = new byte[nonceLen];
        random.nextBytes(nonce);
        return nonce;
    }

}
