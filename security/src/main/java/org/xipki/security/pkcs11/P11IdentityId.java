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

import org.xipki.pkcs11.wrapper.PKCS11Constants;

import static org.xipki.util.Args.notNull;

/**
 * Identifier of {@link P11Identity}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11IdentityId {

  private final P11SlotId slotId;

  private final P11ObjectId keyId;

  private final Long publicKeyHandle;

  /**
   * Constructor.
   *
   * @param slotId Slot identifier. Must not be {@code null}.
   * @param keyId  Object identifier. Must not be {@code null}.
   * @param publicKeyHandle Object handle of the public key, may be {@code null}.
   *
   */
  public P11IdentityId(P11SlotId slotId, P11ObjectId keyId, Long publicKeyHandle) {
    this.slotId = notNull(slotId, "slotId");
    this.keyId = notNull(keyId, "keyId");
    this.publicKeyHandle = (keyId.getObjectCLass() == PKCS11Constants.CKO_SECRET_KEY) ? null : publicKeyHandle;
  }

  public Long getPublicKeyHandle() {
    return publicKeyHandle;
  }

  public P11SlotId getSlotId() {
    return slotId;
  }

  public P11ObjectId getKeyId() {
    return keyId;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof P11IdentityId)) {
      return false;
    }

    P11IdentityId ei = (P11IdentityId) obj;
    return this.slotId.equals(ei.slotId)  && this.keyId.equals(ei.keyId);
  }

  @Override
  public String toString() {
    return "slot " + slotId + ", key " + keyId;
  }

  @Override
  public int hashCode() {
    return slotId.hashCode() + 31 * keyId.hashCode();
  }

}
