// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pki.ErrorCode;
import org.xipki.pki.OperationException;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.ctlog.CtLog;
import org.xipki.security.ctlog.CtLog.DigitallySigned;
import org.xipki.security.ctlog.CtLog.SerializedSCT;
import org.xipki.security.ctlog.CtLog.SignatureAlgorithm;
import org.xipki.security.ctlog.CtLog.SignatureAndHashAlgorithm;
import org.xipki.security.ctlog.CtLog.SignedCertificateTimestamp;
import org.xipki.security.ctlog.CtLog.SignedCertificateTimestampList;
import org.xipki.security.ctlog.CtLogMessages.AddPreChainRequest;
import org.xipki.security.ctlog.CtLogMessages.AddPreChainResponse;
import org.xipki.util.Args;
import org.xipki.util.Curl;
import org.xipki.util.Curl.CurlResult;
import org.xipki.util.DefaultCurl;
import org.xipki.util.Hex;
import org.xipki.util.JSON;
import org.xipki.util.StringUtil;
import org.xipki.util.http.SslContextConf;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Certificate transparency (CT) log client.
 *
 * @author Lijun Liao (xipki)
 */
public class CtLogClient {

  private static final Logger LOG = LoggerFactory.getLogger(CtLogClient.class);

  private final Curl curl;

  private final List<String> addPreChainUrls;

  public CtLogClient(List<String> serverUrls, SslContextConf sslContextConf) {
    Args.notEmpty(serverUrls, "serverUrls");

    this.curl  = new DefaultCurl();
    ((DefaultCurl) this.curl).setSslContextConf(sslContextConf);
    this.addPreChainUrls = new ArrayList<>(serverUrls.size());
    for (String m : serverUrls) {
      String addPreChainUrl = m.endsWith("/") ? m + "ct/v1/add-pre-chain/" : m + "/ct/v1/add-pre-chain/";
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

      byte[] respContent = Optional.ofNullable(res.getContent()).orElseThrow(
          () -> new OperationException(ErrorCode.SYSTEM_FAILURE,
                  "server does not return any content while responding " + url));

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
