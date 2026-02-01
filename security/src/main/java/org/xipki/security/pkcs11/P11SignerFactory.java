// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.DfltConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.SignerConf;
import org.xipki.security.SignerFactory;
import org.xipki.security.X509Cert;
import org.xipki.security.XiContentSigner;
import org.xipki.security.composite.CompositeSigSuite;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.util.codec.Hex;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.misc.StringUtil;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * {@link SignerFactory} for PKCS#11 token.
 *
 * @author Lijun Liao (xipki)
 */
public class P11SignerFactory implements SignerFactory {

  private static final String TYPE = "pkcs11";

  private static final Set<String> types =
      Set.copyOf(Collections.singletonList(TYPE));

  private P11CryptServiceFactory p11CryptServiceFactory;

  private SecurityFactory securityFactory;

  public void setP11CryptServiceFactory(
      P11CryptServiceFactory p11CryptServiceFactory) {
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

  private P11Key getKey(P11Slot slot, byte[] keyId, String keyLabel)
      throws ObjectCreationException {
    String str2 = (keyId != null) ? "id " + Hex.encode(keyId)
        : "label " + keyLabel;
    P11Key key;
    try {
      key = slot.getKey(keyId, keyLabel);
    } catch (TokenException e) {
      throw new ObjectCreationException("error finding identity with "
          + str2 + ": " + e.getMessage(), e);
    }

    if (key == null) {
      throw new ObjectCreationException("unknown identity with " + str2);
    }
    return key;
  }

  @Override
  public ConcurrentContentSigner newSigner(
      String type, SignerConf conf, X509Cert[] certificateChain)
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

    Integer iParallelism;
    try {
      iParallelism = conf.parallelism();
    } catch (InvalidConfException e) {
      throw new ObjectCreationException(e);
    }

    int parallelism = Objects.requireNonNullElseGet(iParallelism,
        () -> securityFactory.dfltSignerParallelism());

    String moduleName = conf.module();
    Integer slotIndex = conf.slot();

    Long slotId = conf.slotId();

    if ((slotIndex == null) == (slotId == null)) {
      throw new ObjectCreationException(
          "exactly one of slot (index) and slot-id must be specified");
    }

    String keyLabel = conf.keyLabel();
    byte[] keyId = conf.keyId();

    if ((keyId == null) == (keyLabel == null)) {
      throw new ObjectCreationException(
          "exactly one of key-id and key-label must be specified");
    }

    P11Slot slot;
    try {
      P11Module module = p11CryptServiceFactory.getP11Module(moduleName);
      P11SlotId p11SlotId = (slotId != null) ? module.getSlotIdForId(slotId)
          : module.getSlotIdForIndex(slotIndex);
      slot = module.getSlot(p11SlotId);
    } catch (TokenException | XiSecurityException ex) {
      throw new ObjectCreationException(ex.getMessage(), ex);
    }

    // check whether it is a composite key
    boolean composite = false;
    if (keyLabel != null) {
      composite = StringUtil.startsWithIgnoreCase(keyLabel,
                    P11CompositeKey.COMPOSITE_LABEL_PREFIX);
    }

    try {
      SignAlgo algo = conf.algo();

      P11Key key = null;
      P11CompositeKey compositeKey = null;
      if (composite) {
        String coreLabel = keyLabel.substring(
                            P11CompositeKey.COMPOSITE_LABEL_PREFIX.length());
        P11Key pqcKey = getKey(slot, null,
                        P11CompositeKey.COMP_PQC_LABEL_PREFIX + coreLabel);
        P11Key tradKey = getKey(slot, null,
                        P11CompositeKey.COMP_TRAD_LABEL_PREFIX + coreLabel);
        CompositeSigSuite algoSuite =
            algo == null ? null : algo.compositeSigAlgoSuite();
        compositeKey = new P11CompositeKey(pqcKey, tradKey, algoSuite);
        if (algo == null) {
          algo = SignAlgo.getInstance(compositeKey, conf);
        }
      } else {
        key = getKey(slot, keyId, keyLabel);
        if (algo == null) {
          algo = SignAlgo.getInstance(key, conf);
        }
      }

      List<XiContentSigner> signers = new ArrayList<>(parallelism);
      PublicKey publicKey = null;
      if (certificateChain != null && certificateChain.length > 0) {
        publicKey = certificateChain[0].publicKey();
      }

      for (int i = 0; i < parallelism; i++) {
        XiContentSigner signer;
        if (compositeKey != null) {
          signer = P11CompositeContentSigner.newInstance(compositeKey, algo,
                    securityFactory.random4Sign(), publicKey);
        } else {
          signer = P11ContentSigner.newInstance(key, algo,
                    securityFactory.random4Sign(), publicKey);
        }

        signers.add(signer);
      }

      DfltConcurrentContentSigner concurrentSigner =
          new DfltConcurrentContentSigner(algo.isMac(), signers);

      if (certificateChain != null) {
        concurrentSigner.setCertificateChain(certificateChain);
      } else {
        concurrentSigner.setPublicKey(
            key != null ? key.publicKey() : compositeKey.publicKey());
      }

      if (algo.isMac()) {
        assert key != null;
        byte[] sha1HashOfKey = key.digestSecretKey(PKCS11T.CKM_SHA_1);
        concurrentSigner.setSha1DigestOfMacKey(sha1HashOfKey);
      }

      return concurrentSigner;
    } catch (TokenException | NoSuchAlgorithmException | InvalidConfException |
             XiSecurityException ex) {
      throw new ObjectCreationException(ex.getMessage(), ex);
    }
  } // method newSigner

}
