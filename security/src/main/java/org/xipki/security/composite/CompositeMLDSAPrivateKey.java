// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.composite;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.xipki.security.KeySpec;
import org.xipki.security.bridge.MLDSAParameterSpec;
import org.xipki.security.bridge.MLDSAPrivateKey;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;
import org.xipki.util.io.IoUtil;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Container of a composite MLDSA private key.
 * @author Lijun Liao (xipki)
 */
public class CompositeMLDSAPrivateKey implements PrivateKey {

  private final MLDSAPrivateKey pqcKey;

  private final PrivateKey tradKey;

  private final CompositeSigSuite suite;

  private final byte[] keyValue;

  public CompositeMLDSAPrivateKey(PrivateKeyInfo privateKeyInfo) throws InvalidKeySpecException {
    this.suite = CompositeSigSuite.getAlgoSuite(privateKeyInfo.getPrivateKeyAlgorithm());
    Args.notNull(suite, "suite");
    this.keyValue = privateKeyInfo.getPrivateKey().getOctets();

    CompSigMldsaVariant pqcVariant = suite.pqcVariant();
    byte[] pqcSk = Arrays.copyOfRange(keyValue, 0, pqcVariant.skSize());
    PrivateKeyInfo pqcSkInfo = KeyUtil.buildPrivateKeyInfo(
        pqcVariant.keySpec().algorithmIdentifier(), pqcSk);

    int off = pqcVariant.skSize();
    byte[] tradSk  = Arrays.copyOfRange(keyValue, off, keyValue.length);
    PrivateKeyInfo tradSkInfo = KeyUtil.buildPrivateKeyInfo(
        suite.tradVariant().keySpec().algorithmIdentifier(), tradSk);

    this.pqcKey = KeyUtil.wrapMLDSAPrivateKey(KeyUtil.getPrivateKey(pqcSkInfo));
    this.tradKey = KeyUtil.getPrivateKey(tradSkInfo);
  }

  public CompositeMLDSAPrivateKey(MLDSAPrivateKey pqcKey, PrivateKey tradKey) {
    this.pqcKey = Args.notNull(pqcKey, "pqcKey");
    this.tradKey  = Args.notNull(tradKey, "tradKey");

    CompSigMldsaVariant pqcVariant = getMldsaVariant(pqcKey.getParameterSpec());

    PrivateKeyInfo tradSkInfo = PrivateKeyInfo.getInstance(tradKey.getEncoded());
    CompSigTradVariant tradVariant = null;
    if (tradKey instanceof RSAPrivateKey) {
      tradVariant = getRsaTradVariant(((RSAPrivateKey) tradKey).getModulus().bitLength());
    } else {
      PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(tradKey.getEncoded());
      KeySpec keySpec = KeySpec.ofAlgorithmIdentifier(pkInfo.getPrivateKeyAlgorithm());
      if (keySpec != null) {
        tradVariant = CompSigTradVariant.ofKeySpec(keySpec);
      }
    }

    if (tradVariant == null) {
      throw new IllegalArgumentException("could not find SigTradVariant for given key");
    }

    this.suite = CompositeSigSuite.ofVariants(pqcVariant, tradVariant);
    if (this.suite == null) {
      throw new IllegalArgumentException("illegal combination of " +
          pqcVariant + " and " + tradKey);
    }

    this.keyValue = IoUtil.concatenate(pqcKey.getSeed(), tradSkInfo.getPrivateKey().getOctets());
  }

  public CompositeSigSuite suite() {
    return suite;
  }

  public byte[] keyValue() {
    return keyValue.clone();
  }

  public MLDSAPrivateKey pqcKey() {
    return pqcKey;
  }

  public PrivateKey tradKey() {
    return tradKey;
  }

  @Override
  public String getAlgorithm() {
    return suite.name().replace('_', '-');
  }

  @Override
  public String getFormat() {
    return "PKCS#8";
  }

  @Override
  public byte[] getEncoded() {
    try {
      return KeyUtil.buildPrivateKeyInfo(suite.algId(), keyValue).getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  static CompSigMldsaVariant getMldsaVariant(MLDSAParameterSpec spec) {
    String pqcParamName = spec.getName();
    if ("ML-DSA-44".equals(pqcParamName)) {
      return CompSigMldsaVariant.mldsa44;
    } else if ("ML-DSA-65".equals(pqcParamName)) {
      return CompSigMldsaVariant.mldsa65;
    } else if ("ML-DSA-87".equals(pqcParamName)) {
      return CompSigMldsaVariant.mldsa87;
    } else {
      throw new IllegalArgumentException("invalid pqcKey");
    }
  }

  static CompSigTradVariant getRsaTradVariant(int modulusBitLen) {
    CompSigTradVariant ret =
            (modulusBitLen == 2048) ? CompSigTradVariant.RSA2048_PSS
          : (modulusBitLen == 3072) ? CompSigTradVariant.RSA3072_PSS
          : (modulusBitLen == 4096) ? CompSigTradVariant.RSA4096_PSS
          : null;
    if (ret == null) {
      throw new IllegalArgumentException("invalid RSA modulusBitLen " + modulusBitLen);
    }
    return ret;
  }

}
