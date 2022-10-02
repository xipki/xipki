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

import org.xipki.util.CompareUtil;
import org.xipki.util.StringUtil;

import static org.xipki.util.Args.notNull;

/**
 * Identifier of {@link P11Identity}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11IdentityId implements Comparable<P11IdentityId> {

  private final P11SlotIdentifier slotId;

  private final P11ObjectIdentifier keyId;

  private final P11ObjectIdentifier publicKeyId;

  private P11ObjectIdentifier certId;

  /**
   * Constructor.
   *
   * @param slotId
   *          Slot identifier. Must not be {@code null}.
   * @param keyId
   *          Object identifier. Must not be {@code null}.
   */
  public P11IdentityId(P11SlotIdentifier slotId, P11ObjectIdentifier keyId) {
    this.slotId = notNull(slotId, "slotId");
    this.keyId = notNull(keyId, "keyId");
    this.publicKeyId = null;
  }

  /**
   * Constructor.
   *
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
                       boolean publicKeyAvailable, String publicKeyLabel,
                       boolean certAvailable, String certLabel) {
    this.slotId = notNull(slotId, "slotId");
    this.keyId = notNull(keyId, "keyId");
    if (publicKeyAvailable) {
      this.publicKeyId = CompareUtil.equalsObject(publicKeyLabel, keyId.getLabel())
          ? keyId : new P11ObjectIdentifier(keyId.getId(), publicKeyLabel);
    } else {
      this.publicKeyId = null;
    }

    if (certAvailable) {
      this.certId = CompareUtil.equalsObject(certLabel, keyId.getLabel())
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

  public void addCertLabel(String certLabel) {
    this.certId = CompareUtil.equalsObject(certLabel, keyId.getLabel())
        ? keyId : new P11ObjectIdentifier(keyId.getId(), certLabel);
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
    notNull(keyLabel, "objectLabel");
    return this.slotId.equals(slotId) && CompareUtil.equalsObject(keyLabel, this.keyId.getLabel());
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
