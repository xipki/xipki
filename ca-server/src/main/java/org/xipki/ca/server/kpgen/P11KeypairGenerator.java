// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.kpgen;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.xipki.ca.api.kpgen.KeypairGenerator;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.EdECConstants;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.P11CryptService;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotId;
import org.xipki.security.util.DSAParameterCache;
import org.xipki.util.Args;
import org.xipki.util.ConfPairs;

import java.io.IOException;
import java.security.spec.DSAParameterSpec;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKF_GENERATE_KEY_PAIR;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_DSA_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_EC_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_EC_MONTGOMERY_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_VENDOR_SM2_KEY_PAIR_GEN;

/**
 * PKCS#11 {@link P11KeypairGenerator}.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 *
 */
public class P11KeypairGenerator extends KeypairGenerator {

  protected final P11CryptServiceFactory cryptServiceFactory;

  protected P11Slot slot;

  public P11KeypairGenerator(P11CryptServiceFactory cryptServiceFactory) {
    this.cryptServiceFactory = Args.notNull(cryptServiceFactory, "cryptService");
  }

  @Override
  public void initialize0(ConfPairs conf) throws XiSecurityException {
    String moduleName = Args.notNull(conf, "conf").value("module");
    String str = conf.value("slot");
    Integer slotIndex = (str == null) ? null : Integer.parseInt(str);

    str = conf.value("slot-id");
    Long slotId = (str == null) ? null : Long.parseLong(str);

    if ((slotIndex == null && slotId == null) || (slotIndex != null && slotId != null)) {
      throw new XiSecurityException("exactly one of slot (index) and slot-id must be specified");
    }

    try {
      P11CryptService p11Service = this.cryptServiceFactory.getP11CryptService(moduleName);
      P11Module module = p11Service.getModule();
      P11SlotId p11SlotId = (slotId != null) ? module.getSlotIdForId(slotId)
          : module.getSlotIdForIndex(slotIndex);
      this.slot = module.getSlot(p11SlotId);

      Set<String> set = new HashSet<>();
      for (String m : keyspecs) {
        String[] tokens = m.split("/");
        switch (tokens[0]) {
          case "RSA":
            if (slot.supportsMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR)) {
              set.add(m);
            }
            break;
          case "DSA":
            if (slot.supportsMechanism(CKM_DSA_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR)) {
              set.add(m);
            }
            break;
          case "EC":
            if (slot.supportsMechanism(CKM_EC_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR)) {
              if (GMObjectIdentifiers.sm2p256v1.getId().equals(tokens[1])) {
                if (slot.supportsMechanism(CKM_VENDOR_SM2_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR)) {
                  set.add(m);
                }
              } else {
                set.add(m);
              }
            }
            break;
          case "ED25519":
          case "ED448":
            if (slot.supportsMechanism(CKM_EC_EDWARDS_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR)) {
              set.add(m);
            }
            break;
          case "X25519":
          case "X448":
            if (slot.supportsMechanism(CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR)) {
              set.add(m);
            }
            break;
        }
      }
      super.keyspecs.clear();
      super.keyspecs.addAll(set);
    } catch (TokenException ex) {
      throw new XiSecurityException("cannot get the slot", ex);
    }
  }

  @Override
  public PrivateKeyInfo generateKeypair(String keyspec) throws XiSecurityException {
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
          return slot.generateDSAKeypairOtf(spec.getP(), spec.getQ(), spec.getG());
        }
        case "ED25519":
        case "ED448":
        case "X25519":
        case "X448": {
          return slot.generateECKeypairOtf(EdECConstants.getCurveOid(keyspec));
        }
        default: {
          throw new IllegalArgumentException("unknown keyspec " + keyspec);
        }
      }
    } catch (TokenException ex) {
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
