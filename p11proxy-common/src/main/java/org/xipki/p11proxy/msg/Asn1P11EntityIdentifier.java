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

package org.xipki.p11proxy.msg;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.BadAsn1ObjectException;
import org.xipki.security.pkcs11.P11EntityIdentifier;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11SlotIdentifier;

/**
 * TODO.
 * <pre>
 * EntityIdentifer ::= SEQUENCE {
 *     slotId     SlotIdentifier,
 *     keyId      KeyIdentifier }
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1P11EntityIdentifier extends ASN1Object {

  private final Asn1P11SlotIdentifier slotId;

  private final Asn1P11ObjectIdentifier objectId;

  private final P11EntityIdentifier entityId;

  public Asn1P11EntityIdentifier(P11SlotIdentifier slotId, P11ObjectIdentifier objectId) {
    ParamUtil.requireNonNull("slotId", slotId);
    ParamUtil.requireNonNull("objectId", objectId);

    this.slotId = new Asn1P11SlotIdentifier(slotId);
    this.objectId = new Asn1P11ObjectIdentifier(objectId);
    this.entityId = new P11EntityIdentifier(slotId, objectId);
  }

  public Asn1P11EntityIdentifier(Asn1P11SlotIdentifier slotId, Asn1P11ObjectIdentifier objectId) {
    this.slotId = ParamUtil.requireNonNull("slotId", slotId);
    this.objectId = ParamUtil.requireNonNull("objectId", objectId);
    this.entityId = new P11EntityIdentifier(slotId.getSlotId(), objectId.getObjectId());
  }

  public Asn1P11EntityIdentifier(P11EntityIdentifier entityId) {
    this.entityId = ParamUtil.requireNonNull("entityId", entityId);
    this.slotId = new Asn1P11SlotIdentifier(entityId.getSlotId());
    this.objectId = new Asn1P11ObjectIdentifier(entityId.getObjectId());
  }

  private Asn1P11EntityIdentifier(ASN1Sequence seq) throws BadAsn1ObjectException {
    Asn1Util.requireRange(seq, 2, 2);
    int idx = 0;
    this.slotId = Asn1P11SlotIdentifier.getInstance(seq.getObjectAt(idx++));
    this.objectId = Asn1P11ObjectIdentifier.getInstance(seq.getObjectAt(idx++));
    this.entityId = new P11EntityIdentifier(slotId.getSlotId(), objectId.getObjectId());
  }

  public static Asn1P11EntityIdentifier getInstance(Object obj) throws BadAsn1ObjectException {
    if (obj == null || obj instanceof Asn1P11EntityIdentifier) {
      return (Asn1P11EntityIdentifier) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new Asn1P11EntityIdentifier((ASN1Sequence) obj);
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
    vector.add(slotId);
    vector.add(objectId);
    return new DERSequence(vector);
  }

  public Asn1P11SlotIdentifier getSlotId() {
    return slotId;
  }

  public Asn1P11ObjectIdentifier getObjectId() {
    return objectId;
  }

  public P11EntityIdentifier getEntityId() {
    return entityId;
  }

}
