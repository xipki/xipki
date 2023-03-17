// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bc;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.xipki.security.EdECConstants;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.*;

import static org.xipki.util.Args.notNull;

/**
 * {@link ContentVerifierProvider} for the signature algorithm EdDSA (Ed25519 and Ed448).
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

    private EdDSAContentVerifier(AlgorithmIdentifier algId, PublicKey verifyKey) {
      this.algId = algId;
      this.algorithm = EdECConstants.getName(algId.getAlgorithm());
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
      } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException ex) {
        throw new RuntimeCryptoException(ex.getMessage());
      } catch (SignatureException ex) {
        return false;
      }
    }

  } // class EdDSAContentVerifier

  private final PublicKey verifyKey;

  public XiEdDSAContentVerifierProvider(PublicKey verifyKey) {
    this.verifyKey = notNull(verifyKey, "verifyKey");
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
  public ContentVerifier get(AlgorithmIdentifier verifierAlgorithmIdentifier) throws OperatorCreationException {
    return new EdDSAContentVerifier(verifierAlgorithmIdentifier, verifyKey);
  }

}
