// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.bouncycastle.operator.ContentSigner;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.composite.CompKemMlkemVariant;
import org.xipki.security.composite.CompKemTradVariant;
import org.xipki.security.composite.CompositeKemSuite;
import org.xipki.security.composite.CompositeKemUtil;
import org.xipki.security.encap.KEMUtil;
import org.xipki.security.encap.KemEncapKey;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.sign.KemHmacSigner;
import org.xipki.security.sign.Signer;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.util.Arrays;

/**
 * TODO
 * PKCS#11 {@link Signer} for composite KEM signers.
 *
 * @author Lijun Liao (xipki)
 */
class P11CompositeMLKEMSigner implements Signer {

  private final byte[] encodedX509AlgId;

  private final KemHmacSigner kemHmacSigner;

  public P11CompositeMLKEMSigner(
      P11CompositeKey identity, SignAlgo signAlgo, KemEncapKey encapKey)
      throws XiSecurityException {
    try {
      this.encodedX509AlgId = signAlgo.algorithmIdentifier().getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }

    CompositeKemSuite algoSuite = identity.kemAlgoSuite();
    CompKemMlkemVariant mlkemVariant = algoSuite.pqcVariant();
    CompKemTradVariant tradVariant = algoSuite.tradVariant();

    byte[] pk = identity.publicKeyData();
    byte[] ct = encapKey.encapulation().encapKey();
    byte[] mlkemCT  = Arrays.copyOfRange(ct, 0, mlkemVariant.ctSize());
    byte[] tradCT  = Arrays.copyOfRange(ct, mlkemVariant.ctSize(), ct.length);
    byte[] tradPk = Arrays.copyOfRange(pk, mlkemVariant.pkSize(), pk.length);
    byte[] mlkemSS, tradSS;

    try {
      mlkemSS = identity.pqcKey().decapsulateKey(PKCS11T.CKM_ML_KEM, null, mlkemCT, 32);
    } catch (TokenException ex) {
      throw new XiSecurityException("could not compute mlkemSS", ex);
    }

    try {
      if (tradVariant == CompKemTradVariant.RSA2048_OAEP ||
          tradVariant == CompKemTradVariant.RSA3072_OAEP ||
          tradVariant == CompKemTradVariant.RSA4096_OAEP) {
        long ckm = PKCS11T.CKM_RSA_PKCS_OAEP;
        P11Params params = new P11Params.P11RSAPkcsOaepParams(
            HashAlgo.SHA256, 0, null);
        tradSS = identity.tradKey().decrypt(ckm, params, tradCT);
      } else {
        long ckm = PKCS11T.CKM_ECDH1_DERIVE;
        P11Params params = new P11Params.P11Ecdh1DeriveParams(PKCS11T.CKD_NULL, null, tradCT);
        tradSS = identity.tradKey().deriveKey(ckm, params, tradVariant.ecdhSize());
      }
    } catch (TokenException ex) {
      throw new XiSecurityException("could not compute tradSS", ex);
    }

    byte[] decapKeyValue = CompositeKemUtil.sha3256Kdf(
        mlkemSS, tradSS, tradCT, tradPk, algoSuite.label());

    byte[] macKeyValue = KEMUtil.doKemDecryptSecret(decapKeyValue, encapKey.encapulation());
    SecretKey macKey = new SecretKeySpec(macKeyValue, "AES");
    this.kemHmacSigner = new KemHmacSigner(encapKey.id(), macKey);
  }

  @Override
  public final byte[] getEncodedX509AlgId() {
    return Arrays.copyOf(encodedX509AlgId, encodedX509AlgId.length);
  }

  @Override
  public ContentSigner x509Signer() {
    return kemHmacSigner.x509Signer();
  }

}
