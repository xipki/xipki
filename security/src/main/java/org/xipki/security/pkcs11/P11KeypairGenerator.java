/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.xipki.password.PasswordResolver;
import org.xipki.security.EdECConstants;
import org.xipki.security.KeypairGenerator;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.DSAParameterCache;
import org.xipki.util.ConfPairs;

import java.io.IOException;
import java.security.spec.DSAParameterSpec;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import static org.xipki.util.Args.notNull;

/**
 * PKCS#11 {@link P11KeypairGenerator}.
 *
 * @author Lijun Liao
 * @since 5.4.0
 *
 */
public class P11KeypairGenerator extends KeypairGenerator {

  protected final P11CryptServiceFactory cryptServiceFactory;

  protected P11Slot slot;

  public P11KeypairGenerator(P11CryptServiceFactory cryptServiceFactory) {
    this.cryptServiceFactory = notNull(cryptServiceFactory, "cryptService");
  }

  @Override
  public void initialize0(ConfPairs conf, PasswordResolver passwordResolver)
      throws XiSecurityException {
    notNull(conf, "conf");

    String moduleName = conf.value("module");
    String str = conf.value("slot");
    Integer slotIndex = (str == null) ? null : Integer.parseInt(str);

    str = conf.value("slot-id");
    Long slotId = (str == null) ? null : Long.parseLong(str);

    if ((slotIndex == null && slotId == null)
        || (slotIndex != null && slotId != null)) {
      throw new XiSecurityException(
          "exactly one of slot (index) and slot-id must be specified");
    }

    try {
      P11CryptService p11Service = this.cryptServiceFactory.getP11CryptService(moduleName);
      P11Module module = p11Service.getModule();
      P11SlotIdentifier p11SlotId;
      if (slotId != null) {
        p11SlotId = module.getSlotIdForId(slotId);
      } else {
        p11SlotId = module.getSlotIdForIndex(slotIndex);
      }
      this.slot = module.getSlot(p11SlotId);

      Set<String> set = new HashSet<>();
      for (String m : keyspecs) {
        String[] tokens = m.split("/");
        switch (tokens[0]) {
          case "RSA":
            if (slot.supportsMechanism(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN)) {
              set.add(m);
            }
            break;
          case "DSA":
            if (slot.supportsMechanism(PKCS11Constants.CKM_DSA_KEY_PAIR_GEN)) {
              set.add(m);
            }
            break;
          case "EC":
            if (slot.supportsMechanism(PKCS11Constants.CKM_EC_KEY_PAIR_GEN)) {
              if (GMObjectIdentifiers.sm2p256v1.getId().equals(tokens[1])) {
                if (slot.supportsMechanism(PKCS11Constants.CKM_VENDOR_SM2_KEY_PAIR_GEN)) {
                  set.add(m);
                }
              } else {
                set.add(m);
              }
            }
            break;
          case "ED25519":
          case "ED448":
            if (slot.supportsMechanism(PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN)) {
              set.add(m);
            }
            break;
          case "X25519":
          case "X448":
            if (slot.supportsMechanism(PKCS11Constants.CKM_EC_MONTGOMERY_KEY_PAIR_GEN)) {
              set.add(m);
            }
            break;
        }
      }
      super.keyspecs.clear();
      super.keyspecs.addAll(set);
    } catch (P11TokenException ex) {
      throw new XiSecurityException("cannot get the slot", ex);
    }
  }

  @Override
  public PrivateKeyInfo generateKeypair(String keyspec)
      throws XiSecurityException {
    if (!supports(keyspec)) {
      throw new XiSecurityException(name + " cannot generate keypair of keyspec " + keyspec);
    }

    String[] tokens = keyspec.split("/");
    String type = tokens[0].toUpperCase(Locale.ROOT);

    try {
      switch (type) {
        case "RSA": {
          int keysize = Integer.parseInt(tokens[1]);
          if (keysize > 4096) {
            throw new XiSecurityException("keysize too large");
          }

          return slot.generateRSAKeypairOtf(keysize, rsaE);
        }
        case "EC": {
          String curveOid = tokens[1];
          if (curveOid.equals(GMObjectIdentifiers.sm2p256v1.getId())) {
            return slot.generateSM2KeypairOtf();
          } else {
            return slot.generateECKeypairOtf(new ASN1ObjectIdentifier(curveOid));
          }
        }
        case "DSA": {
          int pLength = Integer.parseInt(tokens[1]);
          int qLength = Integer.parseInt(tokens[2]);
          DSAParameterSpec spec = DSAParameterCache.getDSAParameterSpec(pLength, qLength, null);
          return slot.generateDSAKeypairOtf0(spec.getP(), spec.getQ(), spec.getG());
        }
        case "ED25519":
        case "ED448": {
          ASN1ObjectIdentifier curveId = EdECConstants.getCurveOid(keyspec);
          return slot.generateECEdwardsKeypairOtf0(curveId);
        }
        case "X25519":
        case "X448": {
          ASN1ObjectIdentifier curveId = EdECConstants.getCurveOid(keyspec);
          return slot.generateECMontgomeryKeypairOtf0(curveId);
        }
        default: {
          throw new IllegalArgumentException("unknown keyspec " + keyspec);
        }
      }
    } catch (P11TokenException ex) {
      throw new XiSecurityException("error generateKeypair for keyspec " + keyspec, ex);
    }
  }

  @Override
  public boolean isHealthy() {
    return true;
  }

  @Override
  public void close() throws IOException {
  }

}
