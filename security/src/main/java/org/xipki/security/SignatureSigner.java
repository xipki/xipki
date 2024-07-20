// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.xipki.util.Args;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * {@link XiContentSigner} based on {@link Signature}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class SignatureSigner implements XiContentSigner {

  private class SignatureStream extends OutputStream {

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

  private final AlgorithmIdentifier sigAlgId;

  private final byte[] encodedSigAlgId;

  private final Signature signer;

  private final SignatureStream stream = new SignatureStream();

  private final PrivateKey key;

  public SignatureSigner(SignAlgo sigAlgo, Signature signer, PrivateKey key) throws XiSecurityException {
    this(sigAlgo.getAlgorithmIdentifier(), signer, key);
  }

  public SignatureSigner(AlgorithmIdentifier sigAlgId, Signature signer, PrivateKey key)
      throws XiSecurityException {
    this.sigAlgId = Args.notNull(sigAlgId, "sigAlgId");
    this.signer = Args.notNull(signer, "signer");
    this.key = Args.notNull(key, "key");
    try {
      this.encodedSigAlgId = sigAlgId.getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }
  }

  @Override
  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return sigAlgId;
  }

  @Override
  public byte[] getEncodedAlgorithmIdentifier() {
    return Arrays.copyOf(encodedSigAlgId, encodedSigAlgId.length);
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
      throw new RuntimeOperatorException("exception obtaining signature: " + ex.getMessage(), ex);
    }
  }

}
