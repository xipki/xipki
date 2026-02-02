// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.verify;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.encap.KEMUtil;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs12.HmacSigner;
import org.xipki.util.codec.Args;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * {@link ContentVerifierProvider} for the signature algorithm ML-KEM-MAC.
 *
 * @author Lijun Liao (xipki)
 */
public class XiKEMContentVerifierProvider implements ContentVerifierProvider {

  private class MyContentVerifier implements ContentVerifier {

    private final AlgorithmIdentifier algId;

    private final HmacSigner verifier;

    private MyContentVerifier(AlgorithmIdentifier algId)
        throws XiSecurityException {
      this.algId = algId;
      this.verifier = new HmacSigner(SignAlgo.HMAC_SHA256, macKey);
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algId;
    }

    @Override
    public OutputStream getOutputStream() {
      return verifier.x509Signer().getOutputStream();
    }

    @Override
    public boolean verify(byte[] expected) {
      ASN1Sequence seq = ASN1Sequence.getInstance(expected);
      // id: will be used to identify the mackey. not used currently.
      // ASN1UTF8String id = (ASN1UTF8String) seq.getObjectAt(0);
      byte[] rawSignature = ((ASN1OctetString) seq.getObjectAt(1)).getOctets();
      byte[] computedMacValue = verifier.x509Signer().getSignature();
      return Arrays.equals(rawSignature, computedMacValue);
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
    byte[] secret = KEMUtil.kmacDerive(ownerMasterKey, 32,
        "XIPKI-KEM".getBytes(StandardCharsets.US_ASCII), rawPkData);
    macKey = new SecretKeySpec(secret, "HMAC");
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
    if (!OIDs.Xipki.id_alg_KEM_HMAC_SHA256.equals(oid)) {
      throw new OperatorCreationException(
          "unsupported verifierAlgorithmIdentifier " + oid.getId());
    }

    try {
      return new MyContentVerifier(verifierAlgorithmIdentifier);
    } catch (XiSecurityException e) {
      throw new OperatorCreationException(e.getMessage());
    }
  }

}
