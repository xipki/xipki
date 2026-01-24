// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.xipki.security.SignAlgo;
import org.xipki.security.XiContentSigner;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.composite.CompositeSigAlgoSuite;
import org.xipki.security.pkcs11.composite.P11CompositeKey;
import org.xipki.util.codec.Args;
import org.xipki.util.io.IoUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * PKCS#11 {@link XiContentSigner} for composite signers.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class P11CompositeContentSigner implements XiContentSigner {

  private static final byte[] prefix =
      "CompositeAlgorithmSignatures2025".getBytes(StandardCharsets.US_ASCII);

  private final P11ContentSigner.DigestOutputStream os;

  private final P11ContentSigner pqcSigner;

  private final P11ContentSigner tradSigner;

  private final CompositeSigAlgoSuite algoSuite;

  private final byte[] encodedAlgorithmIdentifier;

  private final byte[] context;

  private P11CompositeContentSigner(
      P11CompositeKey identity, CompositeSigAlgoSuite algoSuite,
      byte[] context, SecureRandom rnd)
      throws XiSecurityException {
    this.context = context == null ? null : context.clone();
    this.os = new P11ContentSigner.DigestOutputStream(
        algoSuite.ph().createDigest());
    this.algoSuite = Args.notNull(algoSuite, "algoSuite");

    try {
      this.encodedAlgorithmIdentifier = algoSuite.algId().getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }

    this.pqcSigner = P11ContentSigner.newInstance(
        identity.pqcKey(), algoSuite.mldsaVariant().signAlgo(),
        rnd, identity.pqcKey().getPublicKey(), algoSuite.label());
    this.tradSigner = P11ContentSigner.newInstance(
        identity.tradKey(), algoSuite.tradVariant().signAlgo(),
        rnd, identity.tradKey().getPublicKey());
  }

  @Override
  public final byte[] getEncodedAlgorithmIdentifier() {
    return Arrays.copyOf(encodedAlgorithmIdentifier,
            encodedAlgorithmIdentifier.length);
  }

  @Override
  public final AlgorithmIdentifier getAlgorithmIdentifier() {
    return algoSuite.algId();
  }

  @Override
  public OutputStream getOutputStream() {
    this.os.reset();
    return os;
  }

  @Override
  public byte[] getSignature() {
    byte[] digestValue = os.digest();
    byte[] m_ = buildM_(context, digestValue);
    try {
      pqcSigner .getOutputStream().write(m_);
      tradSigner.getOutputStream().write(m_);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    byte[]  pqcSig =  pqcSigner.getSignature();
    byte[] tradSig = tradSigner.getSignature();
    return IoUtil.concatenate(pqcSig, tradSig);
  }

  private byte[] buildM_(byte[] ctx, byte[] digestValue) {
    if (ctx == null) {
      ctx = new byte[0];
    } else {
      Args.max(ctx.length, "ctx.length", 255);
    }

    byte[] lenCtx = new byte[] {(byte) ctx.length};
    return IoUtil.concatenate(prefix, algoSuite.label(), lenCtx, ctx,
            digestValue);
  }

  static P11CompositeContentSigner newInstance(
        P11CompositeKey key, SignAlgo signAlgo, SecureRandom random,
        PublicKey publicKey) throws XiSecurityException {
    if (publicKey != null) {
      key.setPublicKey(publicKey);
    }
    return new P11CompositeContentSigner(key,
        signAlgo.compositeSigAlgoSuite(), null, random);
  }

}
