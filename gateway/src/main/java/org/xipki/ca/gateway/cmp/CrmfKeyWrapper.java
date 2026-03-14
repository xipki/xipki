// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp;

import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.OperatorException;
import org.xipki.security.OIDs;
import org.xipki.security.util.CrmfUtil;

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

  abstract AlgorithmIdentifier getAlgorithmIdentifier();

  abstract byte[] generateWrappedKey(byte[] encryptionKey) throws OperatorException;

  static class RSAOAEPAsymmetricKeyWrapper extends CrmfKeyWrapper {

    private static final AlgorithmIdentifier OAEP_DFLT =
        new AlgorithmIdentifier(OIDs.Algo.id_RSAES_OAEP, new RSAESOAEPparams());

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
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPADDING");
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
      this.algorithmIdentifier = CrmfUtil.buildCrmfAlgId();
      this.rnd = rnd == null ? new SecureRandom() : rnd;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algorithmIdentifier;
    }

    @Override
    public byte[] generateWrappedKey(byte[] keyToWrap) throws OperatorException {
      try {
        return CrmfUtil.wrapCrmfContentEncryptionKey(keyToWrap, publicKey, rnd);
      } catch (Exception ex) {
        throw new OperatorException("error while generateWrappedKey", ex);
      }
    }

  } // class ECIESAsymmetricKeyWrapper

}
