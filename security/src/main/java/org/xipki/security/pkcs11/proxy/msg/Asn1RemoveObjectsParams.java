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

package org.xipki.security.pkcs11.proxy.msg;

import java.io.IOException;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.security.exception.BadAsn1ObjectException;
import org.xipki.security.pkcs11.P11SlotIdentifier;

/**
 * TODO.
 * <pre>
 * RemoveObjectsParams ::= SEQUENCE {
 *     slotId     SlotIdentifier,
 *     id         OCTET STRING OPTIONAL, -- at least one of id and label must be present
 *     label      UTF8String OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1RemoveObjectsParams extends ASN1Object {

  private final P11SlotIdentifier slotId;

  private final byte[] objectId;

  private final String objectLabel;

  public Asn1RemoveObjectsParams(P11SlotIdentifier slotId, byte[] objectId, String objectLabel) {
    ParamUtil.requireNonNull("slotId", slotId);
    if ((objectId == null || objectId.length == 0) && StringUtil.isBlank(objectLabel)) {
      throw new IllegalArgumentException(
          "at least one of objectId and objectLabel must not be null");
    }

    this.objectId = objectId;
    this.objectLabel = objectLabel;
    this.slotId = slotId;
  }

  private Asn1RemoveObjectsParams(ASN1Sequence seq) throws BadAsn1ObjectException {
    Asn1Util.requireRange(seq, 2, 3);
    int idx = 0;
    slotId = Asn1P11SlotIdentifier.getInstance(seq.getObjectAt(idx++)).slotId();
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

    objectId = (asn1Id == null) ? null : Asn1Util.getOctetStringBytes(asn1Id);
    objectLabel = (asn1Label == null) ? null : Asn1Util.getUtf8String(seq.getObjectAt(idx++));

    if ((objectId == null || objectId.length == 0) && StringUtil.isBlank(objectLabel)) {
      throw new BadAsn1ObjectException("invalid object Asn1RemoveObjectsParams: "
          + "at least one of id and label must not be null");
    }
  }

  public static Asn1RemoveObjectsParams getInstance(Object obj) throws BadAsn1ObjectException {
    if (obj == null || obj instanceof Asn1RemoveObjectsParams) {
      return (Asn1RemoveObjectsParams) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new Asn1RemoveObjectsParams((ASN1Sequence) obj);
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
    vector.add(new Asn1P11SlotIdentifier(slotId));
    vector.add(new DERUTF8String(objectLabel));
    return new DERSequence(vector);
  }

  public P11SlotIdentifier slotId() {
    return slotId;
  }

  public byte[] ojectId() {
    return Arrays.copyOf(objectId, objectId.length);
  }

  public String objectLabel() {
    return objectLabel;
  }

}
