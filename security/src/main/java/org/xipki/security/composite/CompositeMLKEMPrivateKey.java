// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.composite;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.xipki.security.KeySpec;
import org.xipki.security.bridge.MLKEMParameterSpec;
import org.xipki.security.bridge.MLKEMPrivateKey;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;
import org.xipki.util.io.IoUtil;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Composite MLKEMPrivate Key.
 * @author Lijun Liao (xipki)
 */
public class CompositeMLKEMPrivateKey implements PrivateKey {

  private final MLKEMPrivateKey pqcKey;

  private final PrivateKey tradKey;

  private final CompositeKemSuite suite;

  private final byte[] keyValue;

  public CompositeMLKEMPrivateKey(PrivateKeyInfo privateKeyInfo)
      throws InvalidKeySpecException {
    this.suite = CompositeKemSuite.getAlgoSuite(privateKeyInfo.getPrivateKeyAlgorithm());
    Args.notNull(suite, "suite");
    this.keyValue = privateKeyInfo.getPrivateKey().getOctets();

    CompKemMlkemVariant pqcVariant = suite.pqcVariant();
    byte[] pqcSk = Arrays.copyOfRange(keyValue, 0, pqcVariant.skSize());
    PrivateKeyInfo pqcSkInfo = KeyUtil.buildPrivateKeyInfo(
        pqcVariant.keySpec().algorithmIdentifier(), pqcSk);

    int off = pqcVariant.skSize();
    byte[] tradSk  = Arrays.copyOfRange(keyValue, off, keyValue.length);
    PrivateKeyInfo tradSkInfo = KeyUtil.buildPrivateKeyInfo(
        suite.tradVariant().keySpec().algorithmIdentifier(), tradSk);

    this.pqcKey =  KeyUtil.wrapMLKEMPrivateKey(KeyUtil.getPrivateKey(pqcSkInfo));
    this.tradKey = KeyUtil.getPrivateKey(tradSkInfo);
  }

  public CompositeMLKEMPrivateKey(MLKEMPrivateKey pqcKey, PrivateKey tradKey) {
    this.pqcKey = Args.notNull(pqcKey, "pqcKey");
    this.tradKey  = Args.notNull(tradKey, "tradKey");

    CompKemMlkemVariant pqcVariant = getPqcVariant(pqcKey.getParameterSpec());
    CompKemTradVariant tradVariant = null;
    PrivateKeyInfo tradSkInfo = PrivateKeyInfo.getInstance(tradKey.getEncoded());
    if (tradKey instanceof RSAPrivateKey) {
      tradVariant = getRsaTradVariant(((RSAPrivateKey) tradKey).getModulus().bitLength());
    } else {
      PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(tradKey.getEncoded());
      KeySpec keySpec = KeySpec.ofAlgorithmIdentifier(pkInfo.getPrivateKeyAlgorithm());
      if (keySpec != null) {
        tradVariant = CompKemTradVariant.ofKeySpec(keySpec);
      }
    }

    if (tradVariant == null) {
      throw new IllegalArgumentException("invalid tradKey");
    }

    this.suite = CompositeKemSuite.ofVariants(pqcVariant, tradVariant);
    if (this.suite == null) {
      throw new IllegalArgumentException("illegal combination of " +
          pqcVariant + " and " + tradKey);
    }

    this.keyValue = IoUtil.concatenate(pqcKey.getSeed(), tradSkInfo.getPrivateKey().getOctets());
  }

  public CompositeKemSuite suite() {
    return suite;
  }

  public byte[] keyValue() {
    return keyValue.clone();
  }

  public MLKEMPrivateKey pqcKey() {
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

  static CompKemMlkemVariant getPqcVariant(MLKEMParameterSpec spec) {
    String pqcParamName = spec.getName();
    if ("ML-KEM-768".equals(pqcParamName)) {
      return CompKemMlkemVariant.mlkem768;
    } else if ("ML-KEM-1024".equals(pqcParamName)) {
      return CompKemMlkemVariant.mlkem1024;
    } else {
      throw new IllegalArgumentException("invalid pqcKey");
    }
  }

  static CompKemTradVariant getRsaTradVariant(int modulusBitLen) {
    CompKemTradVariant ret =
            (modulusBitLen == 2048) ? CompKemTradVariant.RSA2048_OAEP
          : (modulusBitLen == 3072) ? CompKemTradVariant.RSA3072_OAEP
          : (modulusBitLen == 4096) ? CompKemTradVariant.RSA4096_OAEP
          : null;
    if (ret == null) {
      throw new IllegalArgumentException("invalid RSA modulusBitLen " + modulusBitLen);
    }
    return ret;
  }

}
