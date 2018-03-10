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

import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11EntityIdentifier implements Comparable<P11EntityIdentifier> {

  private final P11SlotIdentifier slotId;

  private final P11ObjectIdentifier objectId;

  /**
   * TODO.
   * @param slotId
   *          Slot identifier. Must not be {@code null}.
   * @param objectId
   *          Object identifier. Must not be {@code null}.
   */
  public P11EntityIdentifier(P11SlotIdentifier slotId, P11ObjectIdentifier objectId) {
    this.slotId = ParamUtil.requireNonNull("slotId", slotId);
    this.objectId = ParamUtil.requireNonNull("objectId", objectId);
  }

  public P11SlotIdentifier slotId() {
    return slotId;
  }

  public P11ObjectIdentifier objectId() {
    return objectId;
  }

  @Override
  public int compareTo(P11EntityIdentifier obj) {
    int ct = slotId.compareTo(obj.slotId);
    if (ct != 0) {
      return ct;
    }
    return objectId.compareTo(obj.objectId);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof P11EntityIdentifier)) {
      return false;
    }

    P11EntityIdentifier ei = (P11EntityIdentifier) obj;
    return this.slotId.equals(ei.slotId) && this.objectId.equals(ei.objectId);
  }

  public boolean match(P11SlotIdentifier slotId, String objectLabel) {
    ParamUtil.requireNonNull("objectLabel", objectLabel);
    return this.slotId.equals(slotId) && objectLabel.equals(this.objectId.label());
  }

  @Override
  public String toString() {
    return StringUtil.concatObjects("slot ", slotId, ", object ", objectId);
  }

  @Override
  public int hashCode() {
    int hashCode = slotId.hashCode();
    return hashCode + 31 * objectId.hashCode();
  }

}
