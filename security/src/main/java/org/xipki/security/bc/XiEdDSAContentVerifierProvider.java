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
 * {@link ContentVerifierProvider} for the signature algorithm EdDSA
 * (Ed25519 and Ed448).
 *
 * @author Lijun Liao (xipki)
 * @since 2.1.0
 */

public class XiEdDSAContentVerifierProvider implements ContentVerifierProvider {

  private static class EdDSAContentVerifier implements ContentVerifier {

    private final String algorithm;

    private final AlgorithmIdentifier algId;

    private final ByteArrayOutputStream outstream;

    private final PublicKey verifyKey;

    private EdDSAContentVerifier(
        AlgorithmIdentifier algId, PublicKey verifyKey) {
      this.algId = algId;
      try {
        this.algorithm = SignAlgo.getInstance(algId).getJceName();
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("This shall not happen: " + e.getMessage(),
            e);
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

  } // class EdDSAContentVerifier

  private final PublicKey verifyKey;

  public XiEdDSAContentVerifierProvider(PublicKey verifyKey) {
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
    return new EdDSAContentVerifier(verifierAlgorithmIdentifier, verifyKey);
  }

}
