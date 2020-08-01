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

import static org.xipki.util.Args.notNull;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.X509Cert;
import org.xipki.util.LogUtil;

/**
 * PKCS#11 cryptographic service.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11CryptService {

  private static final Logger LOG = LoggerFactory.getLogger(P11CryptService.class);

  private P11Module module;

  public P11CryptService(P11Module module) throws P11TokenException {
    this.module = notNull(module, "module");
  }

  public synchronized void refresh() throws P11TokenException {
    LOG.info("refreshing PKCS#11 module {}", module.getName());

    List<P11SlotIdentifier> slotIds = module.getSlotIds();
    for (P11SlotIdentifier slotId : slotIds) {
      P11Slot slot;
      try {
        slot = module.getSlot(slotId);
      } catch (P11TokenException ex) {
        LogUtil.warn(LOG, ex, "P11TokenException while initializing slot " + slotId);
        continue;
      } catch (Throwable th) {
        LOG.error("unexpected error while initializing slot " + slotId, th);
        continue;
      }

      slot.refresh();
    }

    LOG.info("refreshed PKCS#11 module {}", module.getName());
  } // method refresh

  public P11Module getModule() throws P11TokenException {
    return module;
  }

  public P11Slot getSlot(P11SlotIdentifier slotId) throws P11TokenException {
    return module.getSlot(slotId);
  }

  public P11Identity getIdentity(P11IdentityId identityId) throws P11TokenException {
    return getIdentity(identityId.getSlotId(), identityId.getKeyId());
  }

  public P11Identity getIdentity(P11SlotIdentifier slotId, P11ObjectIdentifier keyId)
      throws P11TokenException {
    P11Slot slot = module.getSlot(slotId);
    return (slot == null) ? null : slot.getIdentity(keyId);
  }

  public X509Cert getCert(P11SlotIdentifier slotId, P11ObjectIdentifier certId)
      throws P11TokenException {
    P11Slot slot = module.getSlot(slotId);
    return slot == null ? null : slot.getCert(certId);
  }

  @Override
  public String toString() {
    return module.toString();
  }

}
