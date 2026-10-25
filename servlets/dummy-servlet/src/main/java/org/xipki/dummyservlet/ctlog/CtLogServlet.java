// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.dummyservlet.ctlog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.codec.Base64;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.codec.json.JsonBuilder;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.pkix.asn1.cert.CtLog;
import org.xipki.pkix.asn1.cert.CtLog.AddPreChainRequest;
import org.xipki.pkix.asn1.cert.CtLog.AddPreChainResponse;
import org.xipki.pkix.asn1.cert.CtLog.DigitallySigned;
import org.xipki.pkix.asn1.cert.CtLog.HashAlgorithm;
import org.xipki.pkix.asn1.cert.CtLog.SignatureAlgorithm;
import org.xipki.pkix.asn1.cert.CtLog.SignatureAndHashAlgorithm;
import org.xipki.util.http.HttpResponse;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.pkix.util.misc.LogUtil;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.util.List;

/**
 * CT Log Servlet.
 *
 * @author Lijun Liao (xipki)
 */
public class CtLogServlet {

  /**
   * ECCt Log Servlet.
   */
  public static class ECCtLogServlet extends CtLogServlet {
    private static final String privateKey =
        "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCA5yyZCYzCoBiIE" +
        "spXdhwWyhQOmfB6OnhFO/g2UCMxkew==";

    private static final String publicKey =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt13k6XhtxLVQlTmmP9NVgsLF" +
        "2EA2U0Blp2ug1cm7H0ltv7NnrCRq+K87YyiggdGdrKwvDN5/DE1muN/jUditww==";

    public ECCtLogServlet() {
      super(Base64.decode(privateKey), Base64.decode(publicKey));
    }

  }

  /**
   * RSACt Log Servlet.
   */
  public static class RSACtLogServlet extends CtLogServlet {
    private static final String privateKey =
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCNHv1OLJCMm+N19hVH" +
        "ykDhzuoX9V59jCLctkgkdIPOZ59dqosKMRQCROz8Zv8LAPV1HrZgopHCTVkQgcnozifw" +
        "7Hwo9JASWfPujN0StUvzdRUwwrWj+MqYiIfU65jxZgPbJgBV6ZoEt9twvih/uG8mLSXc" +
        "GTMpedROjoDytxU8ebQaJppJX3JQY5pl8CWC2cT/W2J8H3O7sQzps3JreI7LE0pJY9qj" +
        "6/7A0+ZQiWPKhyFAON0EHndyWK3Q0Tvr5dgtH3Bwi9E3og/ZoP2Y6BoUJ+Zxi5Pd7qvm" +
        "wmo+gtw8JNYNNyJFVb0PRUWpOkV0pUrnzHvgBsOFpyWTtFbJX2+FAgMBAAECggEABi6g" +
        "XCdZob9GhKlmH0H9+6Zr3ObT394evNqDaI1uJMGnWpwZATZLMRpB44DDlYDSP/I7fRpC" +
        "Fmf7Cd0VskwttcE2YzjrgtJL/FxRZvtoO18asYsmF+vTPEFm6e30Qkb8zkHo69qS87f2" +
        "NgcukQHMZLi/mtfDxQJgSZy2i2t307FUdIR5RWU9CKkc6jhCw1v3kuCLiYYvcGXl2Fj9" +
        "dC8W8z9e4qiI2ezVA+19QdJkcdTZf8X3/XEBF8lwiJWIMZ0Du2u0AH3tu4reKP3nUYR" +
        "mHxc1kLMoWUaAiOWXIr7Av90XoDiiEJtZ4OxwZKdfHWhPcw7w+rP/9Esys1QPjFUTwQ" +
        "KBgQDSQhyMR+GhgAzivZr6RAmYY8mW3eVzYb+SUacg1CeClSvrQO+/v4t9LLWkmq5I9" +
        "cmlRjoZ50lquggFVQlknaKQ+V/hUFMGQvfCdptxGkZO0MP3ZOo8HC1Tg09l6ymDbrxM" +
        "dy2hxCl3f/wRby1TErsWb6io5wnD5ggU7y61aYMpdQKBgQCr0m2VpC1CVUZCX2DDIa3" +
        "wnKEBjuocTEVGUeNRwP+gMtfu8mRG5l3s9S04aMHYvOf823VJc5e+cxLWIpt0lZQIeo" +
        "IslA6B4rBkZ5BEDZfAEtqOqtaSTSMt0eqtRKVzrQ39HoePMiInCjg74wtF88FKMXwB6" +
        "Axdq0npGDGOb5Zb0QKBgDL6mJVisFBKDdXEBxl6+aCbQTt1Hbb2Ek7VwWHyTooYxQdL" +
        "PVYOiTGWb4wzfOJvxa5u8pNpQqG/7UXtslNU7R+ddyPYJ+kyv4PE4jdwGW/uqjUHoMt" +
        "mQY8oHU4m0G/vn3QiyUuZljxFKcbIYALuXbI47HnXWsTGt1rsCzUtGgIpAoGAYHxgMU" +
        "HqcG92btskeS82gAFUoI1ihdWGqUBeyI/6fDlQ7MuM6AuA/wmHBUA+arlaBLIwILkao" +
        "0X3c+wnI8bDRCeXZfUWWHW13AwUBUMkziVIOglRSQKsGJTilb4Qsu6hBlzYft8GMqoY" +
        "ffi3YebJyiITovZty0Pe01hUq8mZw6ECgYB+wvaG4v6KwCJd+4pLA5MgPHFlUIOAqPM" +
        "y233Hw5+7BL+yW9QNWWqsbo5lJVhbPtN8bRo/KnYRN3Sfe297RKtiTGRq9Nlz+t/oZq" +
        "Bk88vd/pkVO1HmOBf0DLmXISzkVR5j9L56h5lTN2tZYOBQ2XNbb90PLfcDvXUpc/uwt" +
        "Q2/ng==";

    private static final String publicKey =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjR79TiyQjJvjdfYVR8pA4c7" +
        "qF/VefYwi3LZIJHSDzmefXaqLCjEUAkTs/Gb/CwD1dR62YKKRwk1ZEIHJ6M4n8Ox8KP" +
        "SQElnz7ozdErVL83UVMMK1o/jKmIiH1OuY8WYD2yYAVemaBLfbcL4of7hvJi0l3BkzK" +
        "XnUTo6A8rcVPHm0GiaaSV9yUGOaZfAlgtnE/1tifB9zu7EM6bNya3iOyxNKSWPao+v+" +
        "wNPmUIljyochQDjdBB53clit0NE76+XYLR9wcIvRN6IP2aD9mOgaFCfmcYuT3e6r5sJ" +
        "qPoLcPCTWDTciRVW9D0VFqTpFdKVK58x74AbDhaclk7RWyV9vhQIDAQAB";

    public RSACtLogServlet() {
      super(Base64.decode(privateKey), Base64.decode(publicKey));
    }
  }

  private static final Logger LOG = LoggerFactory.getLogger(CtLogServlet.class);

  private final PrivateKey signingKey;

  private final byte[] logId;

  private final String signatureAlgo;

  private final SignatureAndHashAlgorithm signatureAndHashAlgorithm;

  private CtLogServlet(byte[] pkcs8PrivateKeyBytes, byte[] publicKeyInfoBytes) {
    SubjectPublicKeyInfo publicKeyInfo;
    try {
      publicKeyInfo = SubjectPublicKeyInfo.fromEncoded(publicKeyInfoBytes);
    } catch (CodecException e) {
      throw new RuntimeException(e);
    }
    byte[] canonicalizedBytes = publicKeyInfo.getEncoded();
    this.logId = HashAlgo.SHA256.hash(canonicalizedBytes);

    Asn1Oid keyAlgId = publicKeyInfo.getAlgorithm().getAlgorithm();

    SignatureAlgorithm signatureAlgorithm;
    String keyType;
    if (AlgorithmOIDs.id_rsaEncryption.equals(keyAlgId)) {
      keyType = "RSA";
      this.signatureAlgo = "SHA256withRSA";
      signatureAlgorithm = SignatureAlgorithm.rsa;
    } else if (AlgorithmOIDs.id_ecPublicKey.equals(keyAlgId)) {
      keyType = "EC";
      this.signatureAlgo = "SHA256withECDSA";
      signatureAlgorithm = SignatureAlgorithm.ecdsa;
    } else {
      String msg = "unknown key type " + keyAlgId.getId();
      LOG.error(msg);
      throw new IllegalStateException(msg);
    }

    this.signatureAndHashAlgorithm =
        new SignatureAndHashAlgorithm(HashAlgorithm.sha256, signatureAlgorithm);

    try {
      KeyFactory kf = CryptoApiFactory.get().newKeyFactory(keyType);
      this.signingKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8PrivateKeyBytes));
    } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException ex) {
      String msg = "error creating private key";
      LogUtil.error(LOG, ex, msg);
      throw new IllegalStateException(msg + ": " + ex.getMessage());
    }
  }

  protected HttpResponse doPost(XiHttpRequest req) {
    try {
      InputStream is = req.getInputStream();
      JsonMap json = JsonParser.parseMap(is, false);
      AddPreChainRequest req0 = AddPreChainRequest.parse(json);

      List<byte[]> chain = req0.chain();
      if (chain == null || chain.size() < 2) {
        LOG.warn("chain has less than two certificates");
        return new HttpResponse(HttpStatusCode.SC_BAD_REQUEST);
      }

      Certificate cert = Certificate.fromEncoded(chain.get(0));
      Certificate caCert = Certificate.fromEncoded(chain.get(1));
      byte[] issuerKeyHash = HashAlgo.SHA256.hash(caCert.getSubjectPublicKeyInfo().getEncoded());
      byte[] preCertTbsCert = CtLog.getPreCertTbsCert(cert.getTBSCertificate());

      byte sctVersion = 0;
      long timestamp = Clock.systemUTC().millis();

      Signature sig = CryptoApiFactory.get().newSignature(signatureAlgo);
      sig.initSign(signingKey);
      CtLog.update(sig, sctVersion, timestamp, null, issuerKeyHash, preCertTbsCert);
      byte[] signature = sig.sign();
      DigitallySigned digitallySigned =
          new DigitallySigned(signatureAndHashAlgorithm, signature);

      AddPreChainResponse resp0 = new AddPreChainResponse(
          sctVersion, logId, timestamp, null, digitallySigned.getEncoded());

      byte[] respContent = JsonBuilder.toJson(resp0.toJson()).getBytes(StandardCharsets.UTF_8);

      return new HttpResponse(HttpStatusCode.SC_OK, "application/json", null, respContent);
    } catch (Exception ex) {
      LogUtil.error(LOG, ex);
      return new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
    }
  } // method doPost

}
