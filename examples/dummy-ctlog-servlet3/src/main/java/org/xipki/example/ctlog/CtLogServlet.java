// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.example.ctlog;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.HashAlgo;
import org.xipki.security.ctlog.CtLog;
import org.xipki.security.ctlog.CtLog.DigitallySigned;
import org.xipki.security.ctlog.CtLog.HashAlgorithm;
import org.xipki.security.ctlog.CtLog.SignatureAlgorithm;
import org.xipki.security.ctlog.CtLog.SignatureAndHashAlgorithm;
import org.xipki.security.ctlog.CtLogMessages.AddPreChainRequest;
import org.xipki.security.ctlog.CtLogMessages.AddPreChainResponse;
import org.xipki.util.JSON;
import org.xipki.util.LogUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.util.List;

/**
 * HTTP servlet of CT Log server.
 *
 * @author Lijun Liao (xipki)
 */
@SuppressWarnings("serial")
public class CtLogServlet extends HttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(CtLogServlet.class);

  private final PrivateKey signingKey;

  private final byte[] logId;

  private final String signatureAlgo;

  private final SignatureAndHashAlgorithm signatureAndHashAlgorithm;

  public CtLogServlet(byte[] pkcs8PrivateKeyBytes, byte[] publicKeyInfoBytes) {
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKeyInfoBytes);
    byte[] canonicalizedBytes;
    try {
      canonicalizedBytes = publicKeyInfo.getEncoded();
    } catch (IOException ex) {
      String msg = "invalid public key";
      LogUtil.error(LOG, ex, msg);
      throw new IllegalStateException(msg);
    }
    this.logId = HashAlgo.SHA256.hash(canonicalizedBytes);

    ASN1ObjectIdentifier keyAlgId = publicKeyInfo.getAlgorithm().getAlgorithm();

    SignatureAlgorithm signatureAlgorithm;
    String keyType;
    if (PKCSObjectIdentifiers.rsaEncryption.equals(keyAlgId)) {
      keyType = "RSA";
      this.signatureAlgo = "SHA256withRSA";
      signatureAlgorithm = SignatureAlgorithm.rsa;
    } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(keyAlgId)) {
      keyType = "EC";
      this.signatureAlgo = "SHA256withECDSA";
      signatureAlgorithm = SignatureAlgorithm.ecdsa;
    } else {
      String msg = "unknown key type " + keyAlgId.getId();
      LOG.error(msg);
      throw new IllegalStateException(msg);
    }

    this.signatureAndHashAlgorithm = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, signatureAlgorithm);

    try {
      KeyFactory kf = KeyFactory.getInstance(keyType);
      this.signingKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8PrivateKeyBytes));
    } catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
      String msg = "error creating private key";
      LogUtil.error(LOG, ex, msg);
      throw new IllegalStateException(msg + ": " + ex.getMessage());
    }
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException {
    try {
      InputStream is = req.getInputStream();
      AddPreChainRequest req0 = JSON.parseObjectAndClose(is, AddPreChainRequest.class);
      List<byte[]> chain = req0.getChain();
      if (chain == null || chain.size() < 2) {
        String msg = "chain has less than two certificates";
        LOG.warn(msg);
        resp.sendError(HttpServletResponse.SC_BAD_REQUEST, msg);
        return;
      }

      Certificate cert = Certificate.getInstance(chain.get(0));
      Certificate caCert = Certificate.getInstance(chain.get(1));
      byte[] issuerKeyHash = HashAlgo.SHA256.hash(caCert.getSubjectPublicKeyInfo().getEncoded());
      byte[] preCertTbsCert = CtLog.getPreCertTbsCert(cert.getTBSCertificate());

      byte sctVersion = 0;
      long timestamp = Clock.systemUTC().millis();

      Signature sig = Signature.getInstance(signatureAlgo);
      sig.initSign(signingKey);
      CtLog.update(sig, sctVersion, timestamp, null, issuerKeyHash, preCertTbsCert);
      byte[] signature = sig.sign();

      AddPreChainResponse resp0 = new AddPreChainResponse();
      resp0.setSct_version(sctVersion);
      resp0.setId(logId);
      resp0.setTimestamp(timestamp);

      DigitallySigned digitallySigned = new DigitallySigned(signatureAndHashAlgorithm, signature);
      resp0.setSignature(digitallySigned.getEncoded());

      byte[] respContent = JSON.toJSONBytes(resp0);

      resp.setContentType("application/json");
      resp.setContentLengthLong(respContent.length);
      resp.getOutputStream().write(respContent);
      resp.setStatus(HttpServletResponse.SC_OK);
    } catch (Exception ex) {
      LogUtil.error(LOG, ex);
      throw new ServletException(ex.getMessage(), ex);
    }
  } // method doPost

}
