// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.composite;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.security.KeySpec;
import org.xipki.security.bridge.MLKEMPublicKey;
import org.xipki.security.util.Asn1Util;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;
import org.xipki.util.io.IoUtil;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Container of a composite MLKEM public key.
 * @author Lijun Liao (xipki)
 */
public class CompositeMLKEMPublicKey implements PublicKey {

  private final MLKEMPublicKey pqcKey;

  private final PublicKey tradKey;

  private final CompositeKemSuite suite;

  private final byte[] keyValue;

  public CompositeMLKEMPublicKey(SubjectPublicKeyInfo publicKeyInfo)
      throws InvalidKeySpecException {
    this.suite = CompositeKemSuite.getAlgoSuite(publicKeyInfo.getAlgorithm());
    Args.notNull(suite, "suite");
    this.keyValue = Asn1Util.getPublicKeyData(publicKeyInfo);
    CompKemMlkemVariant pqcVariant = suite.pqcVariant();

    byte[] mlkemPk = Arrays.copyOfRange(keyValue, 0, pqcVariant.pkSize());
    SubjectPublicKeyInfo pqcPkInfo = new SubjectPublicKeyInfo(
        pqcVariant.keySpec().algorithmIdentifier(), mlkemPk);

    int off = pqcVariant.pkSize();
    byte[] tradPk  = Arrays.copyOfRange(keyValue, off, keyValue.length);
    SubjectPublicKeyInfo tradPkInfo = new SubjectPublicKeyInfo(
        suite.tradVariant().keySpec().algorithmIdentifier(), tradPk);

    this.pqcKey =  KeyUtil.wrapMLKEMPublicKey(KeyUtil.getPublicKey(pqcPkInfo));
    this.tradKey = KeyUtil.getPublicKey(tradPkInfo);
  }

  public CompositeMLKEMPublicKey(MLKEMPublicKey pqcKey, PublicKey tradKey) {
    this.pqcKey = Args.notNull(pqcKey, "pqcKey");
    this.tradKey  = Args.notNull(tradKey, "tradKey");

    CompKemMlkemVariant pqcVariant =
        CompositeMLKEMPrivateKey.getPqcVariant(pqcKey.getParameterSpec());

    CompKemTradVariant tradVariant = null;
    SubjectPublicKeyInfo tradPkInfo = SubjectPublicKeyInfo.getInstance(tradKey.getEncoded());
    if (tradKey instanceof RSAPublicKey) {
      tradVariant = CompositeMLKEMPrivateKey.getRsaTradVariant(
          ((RSAPublicKey) tradKey).getModulus().bitLength());
    } else {
      SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(tradKey.getEncoded());
      KeySpec keySpec = KeySpec.ofAlgorithmIdentifier(pkInfo.getAlgorithm());
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

    this.keyValue = IoUtil.concatenate(pqcKey.getPublicData(),
        Asn1Util.getPublicKeyData(tradPkInfo));
  }

  public MLKEMPublicKey pqcKey() {
    return pqcKey;
  }

  public PublicKey tradKey() {
    return tradKey;
  }

  public byte[] keyValue() {
    return keyValue;
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
