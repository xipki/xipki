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

package org.xipki.security.pkcs11.proxy.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.security.BadAsn1ObjectException;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.util.Args;

import java.io.IOException;

/**
 * Slot identifier and Object identifier.
 *
 * <pre>
 * SlotIdAndObjectId ::= SEQUENCE {
 *     slotId     SlotIdentifier,
 *     objectId   ObjectIdentifier}
 * </pre>
 *
 * @author Lijun Liao
 */
public class SlotIdAndObjectId extends ProxyMessage {

  private final SlotIdentifier slotId;

  private final ObjectIdentifier objectId;

  public SlotIdAndObjectId(P11SlotIdentifier slotId, P11ObjectIdentifier objectId) {
    Args.notNull(slotId, "slotId");
    Args.notNull(objectId, "objectId");

    this.slotId = new SlotIdentifier(slotId);
    this.objectId = new ObjectIdentifier(objectId);
  }

  public SlotIdAndObjectId(SlotIdentifier slotId, ObjectIdentifier objectId) {
    this.slotId = Args.notNull(slotId, "slotId");
    this.objectId = Args.notNull(objectId, "objectId");
  }

  private SlotIdAndObjectId(ASN1Sequence seq)
      throws BadAsn1ObjectException {
    requireRange(seq, 2, 2);
    int idx = 0;
    this.slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++));
    this.objectId = ObjectIdentifier.getInstance(seq.getObjectAt(idx++));
  }

  public static SlotIdAndObjectId getInstance(Object obj)
      throws BadAsn1ObjectException {
    if (obj == null || obj instanceof SlotIdAndObjectId) {
      return (SlotIdAndObjectId) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new SlotIdAndObjectId((ASN1Sequence) obj);
      } else if (obj instanceof byte[]) {
        return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
      } else {
        throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
      }
    } catch (IOException | IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
    }
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence(new ASN1Encodable[]{slotId, objectId});
  }

  public SlotIdentifier getSlotId() {
    return slotId;
  }

  public ObjectIdentifier getObjectId() {
    return objectId;
  }

} // class SlotIdAndObjectId
