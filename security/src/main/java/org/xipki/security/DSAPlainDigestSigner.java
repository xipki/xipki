// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.xipki.security.util.SignerUtil;
import org.xipki.util.Args;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Plain-DSA signer. The signature is not encoded as ASN.1 structure, but just the
 * concatenation of two integer (r and s) in format of byte array.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */
public class DSAPlainDigestSigner implements Signer {

  private final Digest digest;

  private final DSA dsaSigner;

  private boolean forSigning;

  private int keyBitLen;

  public DSAPlainDigestSigner(DSA signer, Digest digest) {
    this.digest = digest;
    this.dsaSigner = signer;
  }

  @Override
  public void init(boolean forSigning, CipherParameters parameters) {
    this.forSigning = forSigning;

    AsymmetricKeyParameter param = (parameters instanceof ParametersWithRandom)
        ? (AsymmetricKeyParameter) ((ParametersWithRandom) parameters).getParameters()
        : (AsymmetricKeyParameter) parameters;

    Args.notNull(param, "param");
    if (param instanceof ECPublicKeyParameters) {
      keyBitLen = ((ECPublicKeyParameters) param).getParameters().getCurve().getFieldSize();
    } else if (param instanceof ECPrivateKeyParameters) {
      keyBitLen = ((ECPrivateKeyParameters) param).getParameters().getCurve().getFieldSize();
    } else if (param instanceof DSAPublicKeyParameters) {
      keyBitLen = ((DSAPublicKeyParameters) param).getParameters().getQ().bitLength();
    } else if (param instanceof DSAPrivateKeyParameters) {
      keyBitLen = ((DSAPrivateKeyParameters) param).getParameters().getQ().bitLength();
    } else {
      throw new IllegalArgumentException("unknown parameters: " + param.getClass().getName());
    }

    if (forSigning && !param.isPrivate()) {
      throw new IllegalArgumentException("Signing Requires Private Key.");
    }

    if (!forSigning && param.isPrivate()) {
      throw new IllegalArgumentException("Verification Requires Public Key.");
    }

    reset();
    dsaSigner.init(forSigning, parameters);
  } // method init

  @Override
  public void update(byte input) {
    digest.update(input);
  }

  @Override
  public void update(byte[] input, int inOff, int length) {
    digest.update(input, inOff, length);
  }

  @Override
  public byte[] generateSignature() {
    if (!forSigning) {
      throw new IllegalStateException("DSADigestSigner not initialized for signature generation.");
    }

    byte[] hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);

    BigInteger[] sig = dsaSigner.generateSignature(hash);

    try {
      return SignerUtil.dsaSigToPlain(sig[0], sig[1], keyBitLen);
    } catch (XiSecurityException ex) {
      throw new IllegalStateException("unable to encode signature");
    }
  }

  @Override
  public boolean verifySignature(byte[] signature) {
    if (forSigning) {
      throw new IllegalStateException("DSADigestSigner not initialised for verification");
    }

    byte[] hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);

    try {
      BigInteger[] sig = decode(signature);
      return dsaSigner.verifySignature(hash, sig[0], sig[1]);
    } catch (IOException ex) {
      return false;
    }
  }

  @Override
  public void reset() {
    digest.reset();
  }

  private BigInteger[] decode(byte[] encoding) throws IOException {
    int blockSize = (keyBitLen + 7) / 8;
    if (encoding.length != 2 * blockSize) {
      throw new IOException("invalid length of signature");
    }

    BigInteger[] ret = new BigInteger[2];
    byte[] buffer = new byte[blockSize + 1];
    System.arraycopy(encoding, 0, buffer, 1, blockSize);
    ret[0] = new BigInteger(buffer);

    buffer = new byte[blockSize + 1];
    System.arraycopy(encoding, blockSize, buffer, 1, blockSize);
    ret[1] = new BigInteger(buffer);
    return ret;
  }

}
