// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.verify;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * {@link Signature}-based {@link ContentVerifierProvider}.
 *
 * @author Lijun Liao (xipki)
 */
public class SignatureContentVerifierProvider implements ContentVerifierProvider {

  private static final Logger LOG = LoggerFactory.getLogger(SignatureContentVerifierProvider.class);

  private static class MyContentVerifier implements ContentVerifier {

    private final String algorithm;

    private final AlgorithmIdentifier algId;

    private final ByteArrayOutputStream outstream;

    private final PublicKey verifyKey;

    private MyContentVerifier(AlgorithmIdentifier algId, PublicKey verifyKey) {
      this.algId = algId;
      try {
        this.algorithm = SignAlgo.getInstance(algId).jceName();
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("unknown algorithm " +
            algId.getAlgorithm().getId() + ": " + e.getMessage(), e);
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
        Signature sig = Signature.getInstance(algorithm, KeyUtil.providerName(algorithm));
        sig.initVerify(verifyKey);
        sig.update(outstream.toByteArray());
        return sig.verify(expected);
      } catch (SignatureException ex) {
        LOG.warn("could not verify signature", ex);
        return false;
      } catch (GeneralSecurityException ex) {
        LOG.warn("could not verify signature", ex);
        throw new RuntimeException(ex.getMessage());
      }
    }

  } // class EdDSAContentVerifier

  private final PublicKey verifyKey;

  public SignatureContentVerifierProvider(PublicKey verifyKey) {
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
    return new MyContentVerifier(verifierAlgorithmIdentifier, verifyKey);
  }

}
