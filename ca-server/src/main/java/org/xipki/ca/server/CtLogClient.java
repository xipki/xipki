// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.codec.json.JsonBuilder;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.pkix.exception.ErrorCode;
import org.xipki.pkix.exception.OperationException;
import org.xipki.pkix.asn1.cert.CtLog;
import org.xipki.pkix.asn1.cert.CtLog.AddPreChainRequest;
import org.xipki.pkix.asn1.cert.CtLog.AddPreChainResponse;
import org.xipki.pkix.asn1.cert.CtLog.DigitallySigned;
import org.xipki.pkix.asn1.cert.CtLog.SerializedSCT;
import org.xipki.pkix.asn1.cert.CtLog.SignatureAlgorithm;
import org.xipki.pkix.asn1.cert.CtLog.SignatureAndHashAlgorithm;
import org.xipki.pkix.asn1.cert.CtLog.SignedCertificateTimestamp;
import org.xipki.pkix.asn1.cert.CtLog.SignedCertificateTimestampList;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.util.http.Curl;
import org.xipki.util.http.Curl.CurlResult;
import org.xipki.util.http.DefaultCurl;
import org.xipki.util.http.SslContextConf;
import org.xipki.pkix.util.misc.StringUtil;

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
 * CT Log Client.
 *
 * @author Lijun Liao (xipki)
 */
public class CtLogClient {

  private static final Logger LOG = LoggerFactory.getLogger(CtLogClient.class);

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private final Curl curl;

  private final List<String> addPreChainUrls;

  public CtLogClient(List<String> serverUrls, SslContextConf sslContextConf) {
    Args.notEmpty(serverUrls, "serverUrls");

    this.curl  = new DefaultCurl();
    ((DefaultCurl) this.curl).setSslContextConf(sslContextConf);
    this.addPreChainUrls = new ArrayList<>(serverUrls.size());
    for (String m : serverUrls) {
      String addPreChainUrl = m.endsWith("/") ? m + "ct/v1/add-pre-chain/"
          : m + "/ct/v1/add-pre-chain/";

      this.addPreChainUrls.add(addPreChainUrl);
    }
  } // constructor

  public SignedCertificateTimestampList getCtLogScts(
      Certificate precert, X509Cert caCert, List<X509Cert> certchain,
      CtLogPublicKeyFinder publicKeyFinder) throws OperationException {
    List<byte[]> chain = new LinkedList<>();

    byte[] encodedPreCert = precert.getEncoded();
    byte[] issuerKeyHash = HashAlgo.SHA256.hash(caCert.subjectPublicKeyInfo().getEncoded());

    byte[] preCertTbsCert;
    try {
      preCertTbsCert = CtLog.getPreCertTbsCert(precert.getTBSCertificate());
    } catch (CodecException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
    }

    chain.add(encodedPreCert);
    chain.add(caCert.getEncoded());
    if (certchain != null) {
      for (X509Cert m : certchain) {
        chain.add(m.getEncoded());
      }
    }

    AddPreChainRequest request = new AddPreChainRequest(chain);

    byte[] content = StringUtil.toUtf8Bytes(JsonBuilder.toJson(request.toJson()));

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
        throw new OperationException(ErrorCode.SYSTEM_FAILURE,
            "error while calling " + url + ": " + ex.getMessage());
      }

      byte[] respContent = Optional.ofNullable(res.content()).orElseThrow(
          () -> new OperationException(ErrorCode.SYSTEM_FAILURE,
              "server does not return any content while responding " + url));

      String respContentStr = StringUtil.toUtf8String(respContent);
      LOG.debug("CTLog Response: {}", respContentStr);

      AddPreChainResponse resp;
      try {
        JsonMap json = JsonParser.parseMap(respContentStr, false);
        resp = AddPreChainResponse.parse(json);
      } catch (CodecException e) {
        throw new OperationException(ErrorCode.SYSTEM_FAILURE,
            "server does not return any well-formed response", e);
      }

      DigitallySigned ds = DigitallySigned.getInstance(resp.signature(), new AtomicInteger(0));
      byte sctVersion = resp.sct_version();
      byte[] logId = resp.id();
      String hexLogId = Hex.encodeUpper(logId);
      long timestamp = resp.timestamp();
      byte[] extensions = resp.extensions();

      PublicKey verifyKey = publicKeyFinder == null ? null : publicKeyFinder.getPublicKey(logId);
      if (verifyKey == null) {
        LOG.warn("could not find CtLog public key 0x{} to verify the SCT", hexLogId);
      } else {
        SignatureAndHashAlgorithm algorithm = ds.algorithm();
        String signAlgo = getSignatureAlgo(algorithm);

        boolean sigValid;
        try {
          Signature sig = cryptoApi.newSignature(signAlgo);
          sig.initVerify(verifyKey);
          CtLog.update(sig, sctVersion, timestamp, extensions, issuerKeyHash, preCertTbsCert);
          sigValid = sig.verify(ds.signature());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException
                | SignatureException ex) {
          throw new OperationException(ErrorCode.SYSTEM_FAILURE, "error verifying SCT signature");
        }

        if (sigValid) {
          LOG.info("verified SCT signature with logId {} and timestamp {}", hexLogId, timestamp);
        } else {
          throw new OperationException(ErrorCode.SYSTEM_FAILURE, "SCT signature is invalid");
        }
      }

      SignedCertificateTimestamp sct = new SignedCertificateTimestamp(
          sctVersion, logId, timestamp, extensions, ds);
      scts.add(sct);
    }

    return new SignedCertificateTimestampList(new SerializedSCT(scts));
  } // method getCtLogScts

  private static String getSignatureAlgo(SignatureAndHashAlgorithm algorithm)
      throws OperationException {
    String hashName;
    switch (algorithm.hash()) {
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
        throw new OperationException(ErrorCode.SYSTEM_FAILURE,
            "unsupported hash algorithm " + algorithm.hash());
    }

    String encAlgo;
    SignatureAlgorithm signatureType = algorithm.signature();
    if (SignatureAlgorithm.ecdsa == signatureType) {
      encAlgo = "ECDSA";
    } else if (SignatureAlgorithm.rsa == signatureType) {
      encAlgo = "RSA";
    } else {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE,
          "unsupported signature algorithm " + algorithm.signature());
    }

    return hashName + "WITH" + encAlgo;
  }

}
