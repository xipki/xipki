// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bc.compositekem;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xipki.security.KeySpec;
import org.xipki.security.composite.CompositeKemSuite;
import org.xipki.security.composite.KemTradVariant;
import org.xipki.security.composite.MlkemVariant;
import org.xipki.util.codec.Args;
import org.xipki.util.io.IoUtil;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * Container of a composite MLKEM public key.
 * TODO: delete me once composite MLKEM key is supported in BC
 * @deprecated
 * @author Lijun Liao (xipki)
 */
public class CompositeMLKEMPublicKey implements PublicKey {

  private final MLKEMPublicKey mlkemKey;

  private final PublicKey tradKey;

  private final CompositeKemSuite suite;

  private final byte[] keyValue;

  public CompositeMLKEMPublicKey(SubjectPublicKeyInfo publicKeyInfo)
      throws IOException {
    this.suite = CompositeKemSuite.getAlgoSuite(publicKeyInfo.getAlgorithm());
    Args.notNull(suite, "suite");
    this.keyValue = publicKeyInfo.getPublicKeyData().getOctets();
    MlkemVariant mlkemVariant = suite.mlkemVariant();

    byte[] mlkemPk = Arrays.copyOfRange(keyValue, 0, mlkemVariant.pkSize());
    SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(
        mlkemVariant.keySpec().getAlgorithmIdentifier(), mlkemPk);
    this.mlkemKey = (MLKEMPublicKey)
        BouncyCastleProvider.getPublicKey(pkInfo);

    int off = mlkemVariant.pkSize();
    byte[] tradPk  = Arrays.copyOfRange(keyValue, off, keyValue.length);
    pkInfo = new SubjectPublicKeyInfo(
        suite.tradVariant().keySpec().getAlgorithmIdentifier(), tradPk);
    this.tradKey = BouncyCastleProvider.getPublicKey(pkInfo);
  }

  public CompositeMLKEMPublicKey(MLKEMPublicKey mlkemKey, PublicKey tradKey) {
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
    SubjectPublicKeyInfo tradPkInfo =
        SubjectPublicKeyInfo.getInstance(tradKey.getEncoded());
    if (tradKey instanceof RSAPublicKey) {
      RSAPublicKey rKey = (RSAPublicKey) tradKey;
      int size = rKey.getModulus().bitLength();
      tradVariant = (size == 2048) ? KemTradVariant.RSA2048_OAEP
          : (size == 3072) ? KemTradVariant.RSA3072_OAEP
          : (size == 4096) ? KemTradVariant.RSA4096_OAEP : null;
    } else {
      SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(
          tradKey.getEncoded());
      KeySpec keySpec = KeySpec.ofAlgorithmIdentifier(pkInfo.getAlgorithm());
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

    this.keyValue = IoUtil.concatenate(mlkemKey.getPublicData(),
        tradPkInfo.getPublicKeyData().getOctets());
  }

  public MLKEMPublicKey getMlkemKey() {
    return mlkemKey;
  }

  public PublicKey getTradKey() {
    return tradKey;
  }

  public byte[] getKeyValue() {
    return keyValue.clone();
  }

  @Override
  public String getAlgorithm() {
    return suite.name().replace('_', '-');
  }

  @Override
  public String getFormat() {
    return "X509";
  }

  @Override
  public byte[] getEncoded() {
    try {
      return new SubjectPublicKeyInfo(suite.algId(), keyValue).getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

}
