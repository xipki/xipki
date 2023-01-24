/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.pkcs11;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.*;
import org.xipki.util.Hex;
import org.xipki.util.exception.ObjectCreationException;

import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * {@link SignerFactory} for PKCS#11 token.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11SignerFactory implements SignerFactory {

  private static final Logger LOG = LoggerFactory.getLogger(P11SignerFactory.class);

  private static final String TYPE = "pkcs11";

  private static final Set<String> types = Collections.unmodifiableSet(new HashSet<>(Collections.singletonList(TYPE)));

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
      P11SlotIdentifier p11SlotId = (slotId != null) ? module.getSlotIdForId(slotId)
          : module.getSlotIdForIndex(slotIndex);
      slot = module.getSlot(p11SlotId);
    } catch (P11TokenException | XiSecurityException ex) {
      throw new ObjectCreationException(ex.getMessage(), ex);
    }

    String str2 = (keyId != null) ? "id " + Hex.encode(keyId) : "label " + keyLabel;
    P11Identity identity = null;
    try {
      identity = slot.getIdentity(keyId, keyLabel);
    } catch (P11TokenException e) {
      throw new ObjectCreationException("error finding identity with " + str2 + ": " + e.getMessage());
    }

    if (identity == null) {
      throw new ObjectCreationException("unknown identity with " + str2);
    }

    try {
      SignAlgo algo = null;
      String algoName = conf.getConfValue("algo");
      if (algoName != null) {
        algo = SignAlgo.getInstance(algoName);
      }

      if (algo != null && algo.isMac()) {
        P11MacContentSignerBuilder signerBuilder = new P11MacContentSignerBuilder(identity);
        return signerBuilder.createSigner(algo, parallelism);
      } else {
        if (algo == null) {
          algo = SignAlgo.getInstance(identity, conf);
        }

        P11ContentSignerBuilder signerBuilder = new P11ContentSignerBuilder(
            securityFactory, identity, certificateChain);
        return signerBuilder.createSigner(algo, parallelism);
      }
    } catch (P11TokenException | NoSuchAlgorithmException | XiSecurityException ex) {
      throw new ObjectCreationException(ex.getMessage(), ex);
    }
  } // method newSigner

}
