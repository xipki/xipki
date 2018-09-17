/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

import org.xipki.util.CompareUtil;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11IdentityId implements Comparable<P11IdentityId> {

  private final P11SlotIdentifier slotId;

  private final P11ObjectIdentifier keyId;

  private final P11ObjectIdentifier publicKeyId;

  private final P11ObjectIdentifier certId;

  /**
   * TODO.
   * @param slotId
   *          Slot identifier. Must not be {@code null}.
   * @param keyId
   *          Object identifier. Must not be {@code null}.
   * @param publicKeyLabel
   *          Label of the public key
   * @param certLabel
   *          Label of the certificate
   */
  public P11IdentityId(P11SlotIdentifier slotId, P11ObjectIdentifier keyId,
      String publicKeyLabel, String certLabel) {
    this.slotId = ParamUtil.requireNonNull("slotId", slotId);
    this.keyId = ParamUtil.requireNonNull("keyId", keyId);
    if (publicKeyLabel != null) {
      this.publicKeyId = publicKeyLabel.equals(keyId.getLabel())
          ? keyId : new P11ObjectIdentifier(keyId.getId(), publicKeyLabel);
    } else {
      this.publicKeyId = null;
    }

    if (certLabel != null) {
      this.certId = certLabel.equals(keyId.getLabel())
        ? keyId : new P11ObjectIdentifier(keyId.getId(), certLabel);
    } else {
      this.certId = null;
    }
  }

  public P11SlotIdentifier getSlotId() {
    return slotId;
  }

  public P11ObjectIdentifier getKeyId() {
    return keyId;
  }

  public P11ObjectIdentifier getPublicKeyId() {
    return publicKeyId;
  }

  public P11ObjectIdentifier getCertId() {
    return certId;
  }

  @Override
  public int compareTo(P11IdentityId obj) {
    int ct = slotId.compareTo(obj.slotId);
    if (ct != 0) {
      return ct;
    }
    return keyId.compareTo(obj.keyId);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof P11IdentityId)) {
      return false;
    }

    P11IdentityId ei = (P11IdentityId) obj;
    return this.slotId.equals(ei.slotId)
        && this.keyId.equals(ei.keyId)
        && CompareUtil.equalsObject(publicKeyId, ei.publicKeyId)
        && CompareUtil.equalsObject(certId, ei.certId);
  }

  public boolean match(P11SlotIdentifier slotId, String keyLabel) {
    ParamUtil.requireNonNull("objectLabel", keyLabel);
    return this.slotId.equals(slotId) && keyLabel.equals(this.keyId.getLabel());
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("slot ").append(slotId).append(", key ").append(keyId);
    if (publicKeyId != null && publicKeyId != keyId) {
      sb.append(", public key ").append(publicKeyId);
    }
    if (certId != null && certId != keyId) {
      sb.append(", certificate ").append(certId);
    }

    return sb.toString();
  }

  @Override
  public int hashCode() {
    int hashCode = slotId.hashCode() + 31 * keyId.hashCode();
    if (publicKeyId != null) {
      hashCode += 31 * 31 * publicKeyId.hashCode();
    }
    if (certId != null) {
      hashCode += 31 * 31 * 31 * certId.hashCode();
    }
    return hashCode;
  }

}
