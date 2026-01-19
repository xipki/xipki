// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs12.AESGmacContentVerifier;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

/**
 * {@link ContentVerifierProvider} for the signature algorithm ML-KEM-MAC.
 *
 * @author Lijun Liao (xipki)
 */

public class XiKEMContentVerifierProvider implements ContentVerifierProvider {

  private class MyContentVerifier implements ContentVerifier {

    private final AlgorithmIdentifier algId;

    private final ByteArrayOutputStream out;

    private MyContentVerifier(AlgorithmIdentifier algId) {
      this.algId = algId;
      this.out = new ByteArrayOutputStream();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algId;
    }

    @Override
    public OutputStream getOutputStream() {
      out.reset();
      return out;
    }

    @Override
    public boolean verify(byte[] expected) {
      ASN1Sequence seq = ASN1Sequence.getInstance(expected);
      // id: will be used to identify the mackey. not used currently.
      // ASN1UTF8String id = (ASN1UTF8String) seq.getObjectAt(0);
      GCMParameters gcmParameters =
          GCMParameters.getInstance(seq.getObjectAt(1));
      byte[] nonce = gcmParameters.getNonce();
      int tagByteLen = gcmParameters.getIcvLen();
      byte[] rawSignature = ((ASN1OctetString) seq.getObjectAt(2)).getOctets();

      AESGmacContentVerifier mac;
      try {
        mac = new AESGmacContentVerifier(SignAlgo.GMAC_AES256, macKey,
                nonce, tagByteLen);
      } catch (XiSecurityException ex) {
        throw new IllegalStateException(ex.getMessage(), ex);
      }

      try {
        mac.getOutputStream().write(out.toByteArray());
      } catch (IOException e) {
        throw new IllegalStateException(e);
      }

      return mac.verify(rawSignature);
    }

  } // class MyContentVerifier

  private final SecretKey macKey;

  public XiKEMContentVerifierProvider(
      PublicKey verifyKey, SecretKey ownerMasterKey) {
    Args.notNull(verifyKey, "verifyKey");
    Args.notNull(ownerMasterKey, "ownerMasterKey");

    SubjectPublicKeyInfo subjectPublicKeyInfo =
        SubjectPublicKeyInfo.getInstance(verifyKey.getEncoded());
    byte[] rawPkData = subjectPublicKeyInfo.getPublicKeyData().getOctets();
    byte[] secret = KeyUtil.kmacDerive(ownerMasterKey, 32,
        "XIPKI-KEM".getBytes(StandardCharsets.US_ASCII), rawPkData);
    macKey = new SecretKeySpec(secret, "AES");
  }

  @Override
  public boolean hasAssociatedCertificate() {
    return false;
  }

  @Override
  public X509CertificateHolder getAssociatedCertificate() {
    return null;
  }

  @Override
  public ContentVerifier get(AlgorithmIdentifier verifierAlgorithmIdentifier)
      throws OperatorCreationException {
    ASN1ObjectIdentifier oid = verifierAlgorithmIdentifier.getAlgorithm();
    if (!OIDs.Xipki.id_alg_sig_KEM_GMAC_256.equals(oid)) {
      throw new OperatorCreationException(
          "unsupported verifierAlgorithmIdentifier " + oid.getId());
    }

    return new MyContentVerifier(verifierAlgorithmIdentifier);
  }

}
