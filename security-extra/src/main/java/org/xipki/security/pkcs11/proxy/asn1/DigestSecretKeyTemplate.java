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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.security.BadAsn1ObjectException;
import org.xipki.util.Args;

import java.io.IOException;

/**
 * Definition of DigestSecretKeyTemplate.
 *
 * <pre>
 * DigestSecretKeyTemplate ::= SEQUENCE {
 *     slotId         SlotIdentifier,
 *     objectId       ObjectIdentifier,
 *     mechanism      Mechanism}
 * </pre>
 *
 * @author Lijun Liao
 */
public class DigestSecretKeyTemplate extends ProxyMessage {

  private final SlotIdentifier slotId;

  private final ObjectIdentifier objectId;

  private final Mechanism mechanism;

  private DigestSecretKeyTemplate(ASN1Sequence seq)
      throws BadAsn1ObjectException {
    requireRange(seq, 3, 3);
    int idx = 0;
    this.slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++));
    this.objectId = ObjectIdentifier.getInstance(seq.getObjectAt(idx++));
    this.mechanism = Mechanism.getInstance(seq.getObjectAt(idx++));
  }

  public DigestSecretKeyTemplate(SlotIdentifier slotId, ObjectIdentifier objectId,
      long mechanism) {
    this.slotId = Args.notNull(slotId, "slotId");
    this.objectId = Args.notNull(objectId, "objectId");
    this.mechanism = new Mechanism(mechanism, null);
  }

  public static DigestSecretKeyTemplate getInstance(Object obj)
      throws BadAsn1ObjectException {
    if (obj == null || obj instanceof DigestSecretKeyTemplate) {
      return (DigestSecretKeyTemplate) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new DigestSecretKeyTemplate((ASN1Sequence) obj);
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
    vector.add(mechanism);
    return new DERSequence(vector);
  }

  public SlotIdentifier getSlotId() {
    return slotId;
  }

  public ObjectIdentifier getObjectId() {
    return objectId;
  }

  public Mechanism getMechanism() {
    return mechanism;
  }
} // class DigestSecretKeyTemplate
