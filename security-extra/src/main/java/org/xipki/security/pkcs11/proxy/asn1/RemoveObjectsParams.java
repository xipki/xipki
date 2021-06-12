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

import org.bouncycastle.asn1.*;
import org.bouncycastle.util.Arrays;
import org.xipki.security.BadAsn1ObjectException;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

import java.io.IOException;

/**
 * Parameters to remove objects.
 *
 * <pre>
 * RemoveObjectsParams ::= SEQUENCE {
 *     slotId     SlotIdentifier,
 *     id         OCTET STRING OPTIONAL, -- at least one of id and label must be present
 *     label      UTF8String OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao
 */
public class RemoveObjectsParams extends ProxyMessage {

  private final P11SlotIdentifier slotId;

  private final byte[] objectId;

  private final String objectLabel;

  public RemoveObjectsParams(P11SlotIdentifier slotId, byte[] objectId, String objectLabel) {
    Args.notNull(slotId, "slotId");
    if ((objectId == null || objectId.length == 0) && StringUtil.isBlank(objectLabel)) {
      throw new IllegalArgumentException(
          "at least one of objectId and objectLabel must not be null");
    }

    this.objectId = objectId;
    this.objectLabel = objectLabel;
    this.slotId = slotId;
  }

  private RemoveObjectsParams(ASN1Sequence seq)
      throws BadAsn1ObjectException {
    requireRange(seq, 2, 3);
    int idx = 0;
    slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++)).getValue();
    final int size = seq.size();
    ASN1Encodable asn1Id = null;
    ASN1Encodable asn1Label = null;
    if (size == 2) {
      ASN1Encodable asn1 = seq.getObjectAt(1);
      if (asn1 instanceof ASN1String) {
        asn1Label = asn1;
      } else {
        asn1Id = asn1;
      }
    } else {
      asn1Id = seq.getObjectAt(idx++);
      asn1Label = seq.getObjectAt(idx++);
    }

    objectId = (asn1Id == null) ? null : getOctetStringBytes(asn1Id);
    objectLabel = (asn1Label == null) ? null : getUtf8String(seq.getObjectAt(idx++));

    if ((objectId == null || objectId.length == 0) && StringUtil.isBlank(objectLabel)) {
      throw new BadAsn1ObjectException("invalid object RemoveObjectsParams: "
          + "at least one of id and label must not be null");
    }
  }

  public static RemoveObjectsParams getInstance(Object obj)
      throws BadAsn1ObjectException {
    if (obj == null || obj instanceof RemoveObjectsParams) {
      return (RemoveObjectsParams) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new RemoveObjectsParams((ASN1Sequence) obj);
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
    ASN1EncodableVector vector = new ASN1EncodableVector();
    vector.add(new SlotIdentifier(slotId));
    vector.add(new DERUTF8String(objectLabel));
    return new DERSequence(vector);
  }

  public P11SlotIdentifier getSlotId() {
    return slotId;
  }

  public byte[] getOjectId() {
    return objectId == null ? null : Arrays.copyOf(objectId, objectId.length);
  }

  public String getObjectLabel() {
    return objectLabel;
  }

} // class RemoveObjectsParams
