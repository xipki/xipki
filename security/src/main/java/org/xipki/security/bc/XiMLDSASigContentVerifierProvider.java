// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bc;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.xipki.security.SignAlgo;
import org.xipki.util.codec.Args;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * {@link ContentVerifierProvider} for the PQC signature algorithms ML-DSA.
 *
 * @author Lijun Liao (xipki)
 *
 */

public class XiMLDSASigContentVerifierProvider
    implements ContentVerifierProvider {

  private static class PQCContentVerifier implements ContentVerifier {

    private final String algorithm;

    private final AlgorithmIdentifier algId;

    private final ByteArrayOutputStream outstream;

    private final PublicKey verifyKey;

    private PQCContentVerifier(AlgorithmIdentifier algId, PublicKey verifyKey)
        throws OperatorCreationException {
      this.algId = algId;
      try {
        this.algorithm = SignAlgo.getInstance(algId).getJceName();
      } catch (NoSuchAlgorithmException | NullPointerException e) {
        throw new OperatorCreationException(e.getMessage());
      }
      this.outstream = new ByteArrayOutputStream();
      this.verifyKey = verifyKey;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algId;
    }

    @Override
    public OutputStream getOutputStream() {
      outstream.reset();
      return outstream;
    }

    @Override
    public boolean verify(byte[] expected) {
      try {
        Signature sig = Signature.getInstance(algorithm, "BC");
        sig.initVerify(verifyKey);
        sig.update(outstream.toByteArray());
        return sig.verify(expected);
      } catch (SignatureException ex) {
        return false;
      } catch (GeneralSecurityException ex) {
        throw new RuntimeCryptoException(ex.getMessage());
      }
    }

  } // class PQCContentVerifier

  private final PublicKey verifyKey;

  public XiMLDSASigContentVerifierProvider(PublicKey verifyKey) {
    this.verifyKey = Args.notNull(verifyKey, "verifyKey");
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
    return new PQCContentVerifier(verifierAlgorithmIdentifier, verifyKey);
  }

}
