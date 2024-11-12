// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.DfltConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.SignerConf;
import org.xipki.security.SignerFactory;
import org.xipki.security.X509Cert;
import org.xipki.security.XiContentSigner;
import org.xipki.security.XiSecurityException;
import org.xipki.util.Hex;
import org.xipki.util.exception.ObjectCreationException;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * {@link SignerFactory} for PKCS#11 token.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class P11SignerFactory implements SignerFactory {

  private static final String TYPE = "pkcs11";

  private static final Set<String> types = Set.copyOf(Collections.singletonList(TYPE));

  private P11CryptServiceFactory p11CryptServiceFactory;

  private SecurityFactory securityFactory;

  public void setP11CryptServiceFactory(P11CryptServiceFactory p11CryptServiceFactory) {
    this.p11CryptServiceFactory = p11CryptServiceFactory;
  }

  public void setSecurityFactory(SecurityFactory securityFactory) {
    this.securityFactory = securityFactory;
  }

  @Override
  public Set<String> getSupportedSignerTypes() {
    return types;
  }

  @Override
  public boolean canCreateSigner(String type) {
    return types.contains(type.toLowerCase());
  }

  @Override
  public ConcurrentContentSigner newSigner(String type, SignerConf conf, X509Cert[] certificateChain)
      throws ObjectCreationException {
    if (!TYPE.equalsIgnoreCase(type)) {
      throw new ObjectCreationException("unknown signer type " + type);
    }

    if (p11CryptServiceFactory == null) {
      throw new ObjectCreationException("p11CryptServiceFactory is not set");
    }

    if (securityFactory == null) {
      throw new ObjectCreationException("securityFactory is not set");
    }

    String str = conf.getConfValue("parallelism");
    int parallelism = securityFactory.getDfltSignerParallelism();
    if (str != null) {
      try {
        parallelism = Integer.parseInt(str);
      } catch (NumberFormatException ex) {
        throw new ObjectCreationException("invalid parallelism " + str);
      }

      if (parallelism < 1) {
        throw new ObjectCreationException("invalid parallelism " + str);
      }
    }

    String moduleName = conf.getConfValue("module");
    str = conf.getConfValue("slot");
    Integer slotIndex = (str == null) ? null : Integer.parseInt(str);

    str = conf.getConfValue("slot-id");
    Long slotId = (str == null) ? null : Long.parseLong(str);

    if ((slotIndex == null && slotId == null) || (slotIndex != null && slotId != null)) {
      throw new ObjectCreationException("exactly one of slot (index) and slot-id must be specified");
    }

    String keyLabel = conf.getConfValue("key-label");
    str = conf.getConfValue("key-id");
    byte[] keyId = null;
    if (str != null) {
      keyId = Hex.decode(str);
    }

    if ((keyId == null && keyLabel == null) || (keyId != null && keyLabel != null)) {
      throw new ObjectCreationException("exactly one of key-id and key-label must be specified");
    }

    P11Slot slot;
    try {
      P11CryptService p11Service = p11CryptServiceFactory.getP11CryptService(moduleName);
      P11Module module = p11Service.getModule();
      P11SlotId p11SlotId = (slotId != null) ? module.getSlotIdForId(slotId)
          : module.getSlotIdForIndex(slotIndex);
      slot = module.getSlot(p11SlotId);
    } catch (TokenException | XiSecurityException ex) {
      throw new ObjectCreationException(ex.getMessage(), ex);
    }

    String str2 = (keyId != null) ? "id " + Hex.encode(keyId) : "label " + keyLabel;
    P11Key key;
    try {
      key = slot.getKey(keyId, keyLabel);
    } catch (TokenException e) {
      throw new ObjectCreationException("error finding identity with " + str2 + ": " + e.getMessage(), e);
    }

    if (key == null) {
      throw new ObjectCreationException("unknown identity with " + str2);
    }

    try {
      String algoName = conf.getConfValue("algo");
      SignAlgo algo = (algoName != null) ? SignAlgo.getInstance(algoName) : SignAlgo.getInstance(key, conf);

      List<XiContentSigner> signers = new ArrayList<>(parallelism);
      PublicKey publicKey = null;
      if (certificateChain != null && certificateChain.length > 0) {
        publicKey = certificateChain[0].getPublicKey();
      }

      for (int i = 0; i < parallelism; i++) {
        XiContentSigner signer = P11ContentSigner.newInstance(key, algo, securityFactory.getRandom4Sign(), publicKey);
        signers.add(signer);
      }

      DfltConcurrentContentSigner concurrentSigner = new DfltConcurrentContentSigner(algo.isMac(), signers);

      if (certificateChain != null) {
        concurrentSigner.setCertificateChain(certificateChain);
      } else {
        concurrentSigner.setPublicKey(key.getPublicKey());
      }

      if (algo.isMac()) {
        byte[] sha1HashOfKey = key.digestSecretKey(PKCS11Constants.CKM_SHA_1);
        concurrentSigner.setSha1DigestOfMacKey(sha1HashOfKey);
      }

      return concurrentSigner;
    } catch (TokenException | NoSuchAlgorithmException | XiSecurityException ex) {
      throw new ObjectCreationException(ex.getMessage(), ex);
    }
  } // method newSigner

}
