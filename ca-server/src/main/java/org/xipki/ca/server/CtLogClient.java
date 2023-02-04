/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.server;

import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.ctlog.CtLog;
import org.xipki.security.ctlog.CtLog.*;
import org.xipki.security.ctlog.CtLogMessages.AddPreChainRequest;
import org.xipki.security.ctlog.CtLogMessages.AddPreChainResponse;
import org.xipki.security.util.JSON;
import org.xipki.util.*;
import org.xipki.util.Curl.CurlResult;
import org.xipki.util.exception.ErrorCode;
import org.xipki.util.exception.OperationException;
import org.xipki.util.http.SslContextConf;

import java.io.IOException;
import java.security.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Certificate transparency (CT) log client.
 *
 * @author Lijun Liao
 */
public class CtLogClient {

  private static final Logger LOG = LoggerFactory.getLogger(CtLogClient.class);

  private final Curl curl;

  private final List<String> addPreChainUrls;

  public CtLogClient(List<String> serverUrls, SslContextConf sslContextConf) {
    Args.notEmpty(serverUrls, "serverUrls");

    this.curl  = new DefaultCurl(sslContextConf);
    this.addPreChainUrls = new ArrayList<>(serverUrls.size());
    for (String m : serverUrls) {
      String addPreChainUrl = m.endsWith("/") ? m + "ct/v1/add-pre-chain" : m + "/ct/v1/add-pre-chain";
      this.addPreChainUrls.add(addPreChainUrl);
    }
  } // constructor

  public SignedCertificateTimestampList getCtLogScts(
      X509CertificateHolder precert, X509Cert caCert, List<X509Cert> certchain, CtLogPublicKeyFinder publicKeyFinder)
      throws OperationException {
    AddPreChainRequest request = new AddPreChainRequest();
    List<byte[]> chain = new LinkedList<>();
    request.setChain(chain);

    byte[] encodedPreCert;
    try {
      encodedPreCert = precert.getEncoded();
    } catch (IOException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
    }

    byte[] issuerKeyHash;
    try {
      issuerKeyHash = HashAlgo.SHA256.hash(caCert.getSubjectPublicKeyInfo().getEncoded());
    } catch (IOException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
    }

    byte[] preCertTbsCert;
    try {
      preCertTbsCert = CtLog.getPreCertTbsCert(precert.toASN1Structure().getTBSCertificate());
    } catch (IOException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
    }

    chain.add(encodedPreCert);
    chain.add(caCert.getEncoded());
    if (certchain != null) {
      for (X509Cert m : certchain) {
        chain.add(m.getEncoded());
      }
    }

    byte[] content = JSON.toJSONBytes(request);
    if (LOG.isDebugEnabled()) {
      LOG.debug("CTLog Request: {}", StringUtil.toUtf8String(content));
    }

    List<SignedCertificateTimestamp> scts = new ArrayList<>(addPreChainUrls.size());
    Map<String, String> headers = new HashMap<>();
    headers.put("content-type", "application/json");
    for (String url : addPreChainUrls) {
      CurlResult res;
      try {
        res = curl.curlPost(url, false, headers, null, content);
      } catch (Exception ex) {
        throw new OperationException(ErrorCode.SYSTEM_FAILURE, "error while calling " + url + ": " + ex.getMessage());
      }

      byte[] respContent = res.getContent();
      if (respContent == null) {
        throw new OperationException(ErrorCode.SYSTEM_FAILURE,
            "server does not return any content while responding " + url);
      }

      if (LOG.isDebugEnabled()) {
        LOG.debug("CTLog Response: {}", StringUtil.toUtf8String(respContent));
      }

      AddPreChainResponse resp = JSON.parseObject(respContent, AddPreChainResponse.class);

      DigitallySigned ds = DigitallySigned.getInstance(resp.getSignature(), new AtomicInteger(0));
      byte sctVersion = resp.getSct_version();
      byte[] logId = resp.getId();
      String hexLogId = Hex.encodeUpper(logId);
      long timestamp = resp.getTimestamp();
      byte[] extensions = resp.getExtensions();

      PublicKey verifyKey = publicKeyFinder == null ? null : publicKeyFinder.getPublicKey(logId);
      if (verifyKey == null) {
        LOG.warn("could not find CtLog public key 0x{} to verify the SCT", hexLogId);
      } else {
        SignatureAndHashAlgorithm algorithm = ds.getAlgorithm();
        String signAlgo = getSignatureAlgo(algorithm);

        boolean sigValid;
        try {
          Signature sig = Signature.getInstance(signAlgo, "BC");
          sig.initVerify(verifyKey);
          CtLog.update(sig, sctVersion, timestamp, extensions, issuerKeyHash, preCertTbsCert);
          sigValid = sig.verify(ds.getSignature());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException ex) {
          throw new OperationException(ErrorCode.SYSTEM_FAILURE, "error verifying SCT signature");
        }

        if (sigValid) {
          LOG.info("verified SCT signature with logId {} and timestamp {}", hexLogId, timestamp);
        } else {
          throw new OperationException(ErrorCode.SYSTEM_FAILURE, "SCT signature is invalid");
        }
      }

      SignedCertificateTimestamp sct = new SignedCertificateTimestamp(sctVersion, logId, timestamp, extensions, ds);
      scts.add(sct);
    }

    return new SignedCertificateTimestampList(new SerializedSCT(scts));
  } // method getCtLogScts

  private static String getSignatureAlgo(SignatureAndHashAlgorithm algorithm)
      throws OperationException {
    String hashName;
    switch (algorithm.getHash()) {
      case sha1:
        hashName = "SHA1";
        break;
      case sha256:
        hashName = "SHA256";
        break;
      case sha384:
        hashName = "SHA384";
        break;
      case sha512:
        hashName = "SHA512";
        break;
      default:
        throw new OperationException(ErrorCode.SYSTEM_FAILURE, "unsupported hash algorithm " + algorithm.getHash());
    }

    String encAlgo;
    SignatureAlgorithm signatureType = algorithm.getSignature();
    if (SignatureAlgorithm.ecdsa == signatureType) {
      encAlgo = "ECDSA";
    } else if (SignatureAlgorithm.rsa == signatureType) {
      encAlgo = "RSA";
    } else {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE,
          "unsupported signature algorithm " + algorithm.getSignature());
    }

    return hashName + "WITH" + encAlgo;
  }

}
