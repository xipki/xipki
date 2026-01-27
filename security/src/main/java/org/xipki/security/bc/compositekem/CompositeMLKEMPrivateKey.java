// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bc.compositekem;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xipki.security.KeySpec;
import org.xipki.security.composite.CompositeKemSuite;
import org.xipki.security.composite.KemTradVariant;
import org.xipki.security.composite.MlkemVariant;
import org.xipki.util.codec.Args;
import org.xipki.util.io.IoUtil;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

/**
 * Container of a composite MLKEM private key.
 * TODO: delete me once composite MLKEM key is supported in BC
 * @deprecated
 * @author Lijun Liao (xipki)
 */
public class CompositeMLKEMPrivateKey implements PrivateKey {

  private final MLKEMPrivateKey mlkemKey;

  private final PrivateKey tradKey;

  private final CompositeKemSuite suite;

  private final byte[] keyValue;

  public CompositeMLKEMPrivateKey(PrivateKeyInfo privateKeyInfo)
      throws IOException {
    this.suite = CompositeKemSuite.getAlgoSuite(
                  privateKeyInfo.getPrivateKeyAlgorithm());
    Args.notNull(suite, "suite");
    this.keyValue = privateKeyInfo.getPrivateKey().getOctets();

    MlkemVariant mlkemVariant = suite.mlkemVariant();
    byte[] mlkemSk = Arrays.copyOfRange(keyValue, 0, mlkemVariant.skSize());
    PrivateKeyInfo skInfo = new PrivateKeyInfo(
        mlkemVariant.keySpec().getAlgorithmIdentifier(), mlkemSk);
    this.mlkemKey = (MLKEMPrivateKey)
        BouncyCastleProvider.getPrivateKey(skInfo);

    int off = mlkemVariant.skSize();
    byte[] tradSk  = Arrays.copyOfRange(keyValue, off, keyValue.length);
    skInfo = new PrivateKeyInfo(
        suite.tradVariant().keySpec().getAlgorithmIdentifier(), tradSk);
    this.tradKey = BouncyCastleProvider.getPrivateKey(skInfo);
  }

  public CompositeMLKEMPrivateKey(
      MLKEMPrivateKey mlkemKey, PrivateKey tradKey) {
    this.mlkemKey = Args.notNull(mlkemKey, "mlkemKey");
    this.tradKey  = Args.notNull(tradKey, "tradKey");

    MlkemVariant mlkemVariant;
    String mlkemParamName = mlkemKey.getParameterSpec().getName();
    if ("ML-KEM-768".equals(mlkemParamName)) {
      mlkemVariant = MlkemVariant.mlkem768;
    } else if ("ML-KEM-1024".equals(mlkemParamName)) {
      mlkemVariant = MlkemVariant.mlkem1024;
    } else {
      throw new IllegalArgumentException("invalid mlkemKey");
    }

    KemTradVariant tradVariant = null;
    PrivateKeyInfo tradSkInfo =
        PrivateKeyInfo.getInstance(tradKey.getEncoded());
    if (tradKey instanceof RSAPrivateKey) {
      RSAPrivateKey rKey = (RSAPrivateKey) tradKey;
      int size = rKey.getModulus().bitLength();
      tradVariant = (size == 2048) ? KemTradVariant.RSA2048_OAEP
          : (size == 3072) ? KemTradVariant.RSA3072_OAEP
          : (size == 4096) ? KemTradVariant.RSA4096_OAEP : null;
    } else {
      PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(tradKey.getEncoded());
      KeySpec keySpec = KeySpec.ofAlgorithmIdentifier(
          pkInfo.getPrivateKeyAlgorithm());
      if (keySpec != null) {
        tradVariant = KemTradVariant.ofKeySpec(keySpec);
      }
    }

    if (tradVariant == null) {
      throw new IllegalArgumentException("invalid tradKey");
    }

    this.suite = CompositeKemSuite.ofVariants(
        mlkemVariant, tradVariant);
    if (this.suite == null) {
      throw new IllegalArgumentException("illegal combination of " +
          mlkemVariant + " and " + tradKey);
    }

    this.keyValue = IoUtil.concatenate(mlkemKey.getSeed(),
                      tradSkInfo.getPrivateKey().getOctets());
  }

  public CompositeKemSuite getSuite() {
    return suite;
  }

  public byte[] getKeyValue() {
    return keyValue.clone();
  }

  public MLKEMPrivateKey getMlkemKey() {
    return mlkemKey;
  }

  public PrivateKey getTradKey() {
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
      return new PrivateKeyInfo(suite.algId(), keyValue).getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

}
