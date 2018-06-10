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
import org.xipki.ocsp.client.api.OcspRequestorException;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.util.Base64;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;

/**
 * TODO.
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

  private String responderRawPathPost;

  private String responderRawPathGet;

  private HttpClient httpClient;

  public void init(OcspBenchmark responseHandler, String responderUrl, Certificate issuerCert,
      RequestOptions requestOptions, int queueSize) throws Exception {
    ParamUtil.requireNonNull("issuerCert", issuerCert);
    ParamUtil.requireNonNull("responseHandler", responseHandler);
    this.requestOptions = ParamUtil.requireNonNull("requestOptions", requestOptions);

    HashAlgo hashAlgo = HashAlgo.getInstance(requestOptions.getHashAlgorithmId());
    if (hashAlgo == null) {
      throw new OcspRequestorException("unknown HashAlgo "
          + requestOptions.getHashAlgorithmId().getId());
    }

    this.issuerhashAlg = hashAlgo.getAlgorithmIdentifier();
    this.issuerNameHash = new DEROctetString(hashAlgo.hash(issuerCert.getSubject().getEncoded()));
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

    URI uri = new URI(responderUrl);
    this.responderRawPathPost = uri.getRawPath();
    if (this.responderRawPathPost.endsWith("/")) {
      this.responderRawPathGet = this.responderRawPathPost;
    } else {
      this.responderRawPathGet = this.responderRawPathPost + "/";
    }
    this.httpClient = new HttpClient(responderUrl, responseHandler, queueSize);
    this.httpClient.start();
  }

  public void shutdown() throws Exception {
    httpClient.shutdown();
  }

  public void ask(BigInteger[] serialNumbers) throws OcspRequestorException {
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
      String newRawpath = StringUtil.concat(responderRawPathGet, urlEncodedReq);
      request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
          HttpMethod.GET, newRawpath);
    } else {
      ByteBuf content = Unpooled.wrappedBuffer(ocspReq);
      request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
          HttpMethod.POST, responderRawPathPost, content);
      request.headers().addInt("Content-Length", content.readableBytes());
    }
    request.headers().add("Content-Type", "application/ocsp-request");

    httpClient.send(request);
  } // method ask

  private byte[] buildRequest(BigInteger[] serialNumbers) throws OcspRequestorException {
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

      byte[] request = reqBuilder.build().getEncoded();
      if (canCache) {
        requests.put(serialNumbers[0], request);
      }
      return request;
    } catch (OCSPException | IOException ex) {
      throw new OcspRequestorException(ex.getMessage(), ex);
    }
  } // method buildRequest

  private byte[] nextNonce(int nonceLen) {
    byte[] nonce = new byte[nonceLen];
    random.nextBytes(nonce);
    return nonce;
  }

}
