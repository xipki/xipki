// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.verify;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.xipki.security.SignAlgo;
import org.xipki.security.composite.CompositeMLDSAPublicKey;
import org.xipki.security.composite.CompositeSigUtil;
import org.xipki.security.util.DigestOutputStream;
import org.xipki.util.codec.Args;

import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Composite MLDSAContent Verifier Provider.
 *
 * @author Lijun Liao (xipki)
 */
public class CompositeMLDSAContentVerifierProvider implements ContentVerifierProvider {

  private class MyContentVerifier implements ContentVerifier {

    private final AlgorithmIdentifier algId;

    private final DigestOutputStream os;

    private MyContentVerifier(AlgorithmIdentifier algId) {
      this.algId = algId;
      SignAlgo signAlgo;
      try {
        signAlgo = SignAlgo.getInstance(algId);
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("unknown algorithm " +
            algId.getAlgorithm().getId() + ": " + e.getMessage(), e);
      }

      if (!signAlgo.isCompositeMLDSA()) {
        throw new RuntimeException("algorithm " +
            algId.getAlgorithm().getId() + " is not composite MLDSA");
      }
      this.os = new DigestOutputStream(signAlgo.compositeSigAlgoSuite().ph().createDigest());
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algId;
    }

    @Override
    public OutputStream getOutputStream() {
      os.reset();
      return os;
    }

    @Override
    public boolean verify(byte[] signature) {
      try {
        byte[] digestValue = os.digest();
        return CompositeSigUtil.verifyHash(verifyKey, context, digestValue, signature);
      } catch (SignatureException ex) {
        return false;
      } catch (GeneralSecurityException ex) {
        throw new RuntimeException(ex.getMessage());
      }
    }

  } // class EdDSAContentVerifier

  private final CompositeMLDSAPublicKey verifyKey;

  // currently no context is supported
  private final byte[] context = new byte[0];

  public CompositeMLDSAContentVerifierProvider(CompositeMLDSAPublicKey verifyKey) {
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
    return new MyContentVerifier(verifierAlgorithmIdentifier);
  }

}
