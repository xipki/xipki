// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp;

import org.xipki.codec.asn1.OperatorException;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.RSAESOAEPParams;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.pkix.cmp.CmpUtil;

import javax.crypto.Cipher;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;

/**
 * CRMF key wrapper.
 *
 * @author Lijun Liao (xipki)
 */
abstract class CrmfKeyWrapper {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  abstract AlgorithmIdentifier getAlgorithmIdentifier();

  abstract byte[] generateWrappedKey(byte[] encryptionKey) throws OperatorException;

  static class RSAOAEPAsymmetricKeyWrapper extends CrmfKeyWrapper {

    private static final AlgorithmIdentifier OAEP_DFLT =
        AlgorithmIdentifier.build(AlgorithmOIDs.id_RSAES_OAEP, new RSAESOAEPParams());

    private final PublicKey publicKey;

    public RSAOAEPAsymmetricKeyWrapper(PublicKey publicKey) {
      this.publicKey = publicKey;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return OAEP_DFLT;
    }

    @Override
    public byte[] generateWrappedKey(byte[] encryptionKey) throws OperatorException {
      try {
        Cipher cipher = cryptoApi.newCipher("RSA/NONE/OAEPPADDING");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(encryptionKey);
      } catch (Exception ex) {
        throw new OperatorException("error in generateWrappedKey", ex);
      }
    }

  } // class RSAOAEPAsymmetricKeyWrapper

  static class ECIESAsymmetricKeyWrapper extends CrmfKeyWrapper {

    private final AlgorithmIdentifier algorithmIdentifier;

    private final ECPublicKey publicKey;

    private final SecureRandom rnd;

    public ECIESAsymmetricKeyWrapper(ECPublicKey publicKey, SecureRandom rnd) {
      this.publicKey = publicKey;
      this.algorithmIdentifier = CmpUtil.buildCrmfAlgId();
      this.rnd = rnd == null ? new SecureRandom() : rnd;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algorithmIdentifier;
    }

    @Override
    public byte[] generateWrappedKey(byte[] keyToWrap) throws OperatorException {
      try {
        return CmpUtil.wrapCrmfContentEncryptionKey(keyToWrap, publicKey, rnd);
      } catch (Exception ex) {
        throw new OperatorException("error while generateWrappedKey", ex);
      }
    }

  } // class ECIESAsymmetricKeyWrapper

}
