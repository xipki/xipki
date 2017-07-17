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

package org.xipki.ocsp.qa.benchmark;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

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
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.xipki.common.util.Base64;
import org.xipki.common.util.ParamUtil;
import org.xipki.ocsp.client.api.OcspRequestorException;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.security.HashAlgoType;
import org.xipki.security.ObjectIdentifiers;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

class OcspBenchRequestor {

    public static final int MAX_LEN_GET = 190;

    private final Extension[] extnType = new Extension[0];

    private final SecureRandom random = new SecureRandom();

    private static final ConcurrentHashMap<BigInteger, byte[]> requests = new ConcurrentHashMap<>();

    private AlgorithmIdentifier issuerhashAlg;

    private ASN1OctetString issuerNameHash;

    private ASN1OctetString issuerKeyHash;

    private Extension[] extensions;

    private RequestOptions requestOptions;

    private String responderRawPath;

    private HttpClient httpClient;

    public void init(OcspBenchmark responseHandler,
            String responderUrl, Certificate issuerCert, RequestOptions requestOptions)
            throws Exception {
        ParamUtil.requireNonNull("issuerCert", issuerCert);
        ParamUtil.requireNonNull("responseHandler", responseHandler);
        this.requestOptions = ParamUtil.requireNonNull("requestOptions", requestOptions);

        HashAlgoType hashAlgo = HashAlgoType.getHashAlgoType(
                requestOptions.hashAlgorithmId());
        if (hashAlgo == null) {
            throw new OcspRequestorException("unknown HashAlgo "
                    + requestOptions.hashAlgorithmId().getId());
        }

        this.issuerhashAlg = hashAlgo.algorithmIdentifier();
        this.issuerNameHash = new DEROctetString(hashAlgo.hash(
                        issuerCert.getSubject().getEncoded()));
        this.issuerKeyHash = new DEROctetString(hashAlgo.hash(
                        issuerCert.getSubjectPublicKeyInfo().getPublicKeyData().getOctets()));

        List<AlgorithmIdentifier> prefSigAlgs = requestOptions.preferredSignatureAlgorithms();
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

        URI uri = new URI(responderUrl);
        this.responderRawPath = uri.getRawPath();
        if (!this.responderRawPath.endsWith("/")) {
            this.responderRawPath += "/";
        }
        this.httpClient = new HttpClient(responderUrl, responseHandler);
        this.httpClient.start();
    }

    public void shutdown() throws Exception {
        httpClient.shutdown();
    }

    public void ask(final BigInteger[] serialNumbers)
            throws OcspRequestorException {
        byte[] ocspReq = buildRequest(serialNumbers);
        int size = ocspReq.length;

        FullHttpRequest request;

        if (size <= MAX_LEN_GET && requestOptions.isUseHttpGetForRequest()) {
            String b64Request = Base64.encodeToString(ocspReq);
            String urlEncodedReq;
            try {
                urlEncodedReq = URLEncoder.encode(b64Request, "UTF-8");
            } catch (UnsupportedEncodingException ex) {
                throw new OcspRequestorException(ex.getMessage());
            }
            StringBuilder urlBuilder = new StringBuilder();
            urlBuilder.append(responderRawPath);
            urlBuilder.append(urlEncodedReq);
            String newRawpath = urlBuilder.toString();

            request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
                    HttpMethod.GET, newRawpath);
        } else {
            ByteBuf content = Unpooled.wrappedBuffer(ocspReq);
            request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
                    HttpMethod.POST, responderRawPath, content);
            request.headers().addInt("Content-Length", content.readableBytes());
        }
        request.headers().add("Content-Type", "application/ocsp-request");

        httpClient.send(request);
    } // method ask

    private byte[] buildRequest(final BigInteger[] serialNumbers)
            throws OcspRequestorException {
        boolean canCache = (serialNumbers.length == 1) && !requestOptions.isUseNonce();
        if (canCache) {
            byte[] request = requests.get(serialNumbers[0]);
            if (request != null) {
               return request;
            }
        }

        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();

        if (requestOptions.isUseNonce() || extensions != null) {
            List<Extension> extns = new ArrayList<>(2);
            if (requestOptions.isUseNonce()) {
                Extension extn = new Extension(
                        OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                        new DEROctetString(nextNonce(requestOptions.nonceLen())));
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

            byte[] request = reqBuilder.build().getEncoded();
            if (canCache) {
                requests.put(serialNumbers[0], request);
            }
            return request;
        } catch (OCSPException | IOException ex) {
            throw new OcspRequestorException(ex.getMessage(), ex);
        }
    } // method buildRequest

    private byte[] nextNonce(final int nonceLen) {
        byte[] nonce = new byte[nonceLen];
        random.nextBytes(nonce);
        return nonce;
    }

}
