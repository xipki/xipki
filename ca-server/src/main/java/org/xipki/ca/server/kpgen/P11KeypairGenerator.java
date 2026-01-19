// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.kpgen;

import org.xipki.ca.api.kpgen.KeypairGenerator;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.KeyInfoPair;
import org.xipki.security.KeySpec;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotId;
import org.xipki.util.codec.Args;
import org.xipki.util.conf.ConfPairs;

import java.io.IOException;

/**
 * PKCS#11 {@link P11KeypairGenerator}.
 *
 * @author Lijun Liao
 *
 *
 */
public class P11KeypairGenerator extends KeypairGenerator {

  protected final P11CryptServiceFactory cryptServiceFactory;

  protected P11Slot slot;

  public P11KeypairGenerator(P11CryptServiceFactory cryptServiceFactory) {
    this.cryptServiceFactory = Args.notNull(cryptServiceFactory,
        "cryptService");
  }

  @Override
  public void initialize0(ConfPairs conf) throws XiSecurityException {
    String moduleName = Args.notNull(conf, "conf").value("module");
    String str = conf.value("slot");
    Integer slotIndex = (str == null) ? null : Integer.parseInt(str);

    str = conf.value("slot-id");
    Long slotId = (str == null) ? null : Long.parseLong(str);

    if ((slotIndex == null && slotId == null)
        || (slotIndex != null && slotId != null)) {
      throw new XiSecurityException("exactly one of slot (index) and " +
          "slot-id must be specified");
    }

    try {
      P11Module module = this.cryptServiceFactory.getP11Module(moduleName);
      P11SlotId p11SlotId = (slotId != null) ? module.getSlotIdForId(slotId)
          : module.getSlotIdForIndex(slotIndex);
      this.slot = module.getSlot(p11SlotId);
    } catch (TokenException ex) {
      throw new XiSecurityException("cannot get the slot", ex);
    }
  }

  @Override
  public KeyInfoPair generateKeypair(KeySpec keyspec)
      throws XiSecurityException {
    if (!supports(keyspec)) {
      throw new XiSecurityException(name +
          " cannot generate keypair of keyspec " + keyspec);
    }

    return slot.generateKeyPairOtf(keyspec);
  }

  @Override
  public boolean isHealthy() {
    return true;
  }

  @Override
  public void close() throws IOException {
  }

}
