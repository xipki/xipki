// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.sign;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.xipki.security.SignAlgo;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.util.codec.Args;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * {@link Signer} based on {@link Signature}.
 *
 * @author Lijun Liao (xipki)
 */
public class SignatureSigner implements Signer {

  private static class SignatureStream extends OutputStream {

    private final Signature signer;

    private SignatureStream(Signature signer) {
      this.signer = signer;
    }

    public byte[] getSignature() throws SignatureException {
      return signer.sign();
    }

    @Override
    public void write(int singleByte) throws IOException {
      try {
        signer.update((byte) singleByte);
      } catch (SignatureException ex) {
        throw new IOException(ex.getMessage(), ex);
      }
    }

    @Override
    public void write(byte[] bytes) throws IOException {
      try {
        signer.update(bytes);
      } catch (SignatureException ex) {
        throw new IOException(ex.getMessage(), ex);
      }
    }

    @Override
    public void write(byte[] bytes, int off, int len) throws IOException {
      try {
        signer.update(bytes, off, len);
      } catch (SignatureException ex) {
        throw new IOException(ex.getMessage(), ex);
      }
    }

  } // class SignatureStream

  private final byte[] encodedX509SigAlgId;

  private final ContentSigner x509Signer;

  public SignatureSigner(SignAlgo sigAlgo, Signature signer, PrivateKey key)
      throws XiSecurityException {
    this(sigAlgo.algorithmIdentifier(), signer, key);
  }

  public SignatureSigner(AlgorithmIdentifier sigAlgId, Signature signer,
                         PrivateKey key)
      throws XiSecurityException {
    Args.notNull(sigAlgId, "sigAlgId");
    Args.notNull(signer, "signer");
    Args.notNull(key, "key");
    try {
      this.encodedX509SigAlgId = sigAlgId.getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }

    this.x509Signer = new ContentSigner() {
      private final SignatureStream stream = new SignatureStream(signer);

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return sigAlgId;
      }

      @Override
      public OutputStream getOutputStream() {
        try {
          signer.initSign(key);
        } catch (InvalidKeyException ex) {
          throw new RuntimeOperatorException("could not initSign", ex);
        }
        return stream;
      }

      @Override
      public byte[] getSignature() {
        try {
          return stream.getSignature();
        } catch (SignatureException ex) {
          throw new RuntimeOperatorException(
              "exception obtaining signature: " + ex.getMessage(), ex);
        }
      }
    };
  }

  @Override
  public ContentSigner x509Signer() {
    return x509Signer;
  }

  @Override
  public byte[] getEncodedX509AlgId() {
    return Arrays.copyOf(encodedX509SigAlgId, encodedX509SigAlgId.length);
  }

}
