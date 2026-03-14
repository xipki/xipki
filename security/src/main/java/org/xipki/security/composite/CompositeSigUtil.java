// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.composite;

import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;
import org.xipki.util.io.IoUtil;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class CompositeSigUtil {

  private static final byte[] prefix =
      "CompositeAlgorithmSignatures2025".getBytes(StandardCharsets.US_ASCII);

  public static byte[] buildM_(CompositeSigSuite suite, byte[] ctx, byte[] digestValue) {
    if (ctx == null) {
      ctx = new byte[0];
    } else {
      Args.max(ctx.length, "ctx.length", 255);
    }

    byte[] lenCtx = new byte[] {(byte) ctx.length};
    return IoUtil.concatenate(prefix, suite.label(), lenCtx, ctx, digestValue);
  }

  public static boolean verifyHash(
      CompositeMLDSAPublicKey verifyKey, byte[] context, byte[] digestValue, byte[] signature)
      throws NoSuchAlgorithmException, NoSuchProviderException,
        InvalidKeyException, SignatureException {
    CompositeSigSuite suite = verifyKey.suite();
    byte[] pqcSignature = Arrays.copyOfRange(signature, 0, suite.pqcVariant().sigSize());
    byte[] tradSignature = Arrays.copyOfRange(signature,
        suite.pqcVariant().sigSize(), signature.length);

    byte[] m_ = CompositeSigUtil.buildM_(suite, context, digestValue);

    Signature sig = Signature.getInstance(suite.tradVariant().signAlgo().jceName(),
                        KeyUtil.tradProviderName());
    KeyUtil.initVerify(sig, verifyKey.tradKey());
    sig.update(m_);
    boolean sigValid = sig.verify(tradSignature);
    if (!sigValid) {
      return false;
    }

    sig = Signature.getInstance(suite.pqcVariant().signAlgo().jceName(), KeyUtil.pqcProviderName());
    KeyUtil.initVerify(sig, verifyKey.pqcKey());
    try {
      KeyUtil.setContext(sig, suite.label());
    } catch (InvalidAlgorithmParameterException e) {
      throw new SignatureException(e);
    }
    sig.update(m_);
    return sig.verify(pqcSignature);
  }

}
