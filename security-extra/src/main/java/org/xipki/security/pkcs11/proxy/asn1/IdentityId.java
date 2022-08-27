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
import org.xipki.security.BadAsn1ObjectException;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.util.Args;

import java.io.IOException;

/**
 * Identifier of the PKCS#11 identity.
 *
 * <pre>
 * IdentityIdentifer ::= SEQUENCE {
 *     slotId              SlotIdentifier,
 *     keyId               ObjectIdentifier,
 *     publicKeyLabel  [1] UTF8 STRING OPTIONAL,
 *     certLabel       [2] UTF8 STRING OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao
 */
public class IdentityId extends ProxyMessage {

  private final P11IdentityId value;

  public IdentityId(P11IdentityId value) {
    this.value = Args.notNull(value, "value");
  }

  private IdentityId(ASN1Sequence seq) throws BadAsn1ObjectException {
    requireRange(seq, 2, 4);
    P11SlotIdentifier slotId = SlotIdentifier.getInstance(seq.getObjectAt(0)).getValue();
    P11ObjectIdentifier keyId = ObjectIdentifier.getInstance(seq.getObjectAt(1)).getValue();
    String publicKeyLabel = null;
    String certLabel = null;

    final int n = seq.size();
    for (int i = 2; i < n; i++) {
      ASN1Encodable asn1 = seq.getObjectAt(i);
      if (asn1 instanceof ASN1TaggedObject) {
        ASN1TaggedObject tagAsn1 = (ASN1TaggedObject) asn1;
        int tag = tagAsn1.getTagNo();
        if (tag == 1) {
          publicKeyLabel = ASN1UTF8String.getInstance(tagAsn1.getBaseObject()).getString();
        } else if (tag == 2) {
          certLabel = ASN1UTF8String.getInstance(tagAsn1.getBaseObject()).getString();
        }
      }

    }

    this.value = new P11IdentityId(slotId, keyId, publicKeyLabel, certLabel);
  }

  public static IdentityId getInstance(Object obj) throws BadAsn1ObjectException {
    if (obj == null || obj instanceof IdentityId) {
      return (IdentityId) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new IdentityId((ASN1Sequence) obj);
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
    vector.add(new SlotIdentifier(value.getSlotId()));
    vector.add(new ObjectIdentifier(value.getKeyId()));

    if (value.getPublicKeyId() != null) {
      String label = value.getPublicKeyId().getLabel();
      vector.add(new DERTaggedObject(true, 1, new DERUTF8String(label)));
    }

    if (value.getCertId() != null) {
      String label = value.getCertId().getLabel();
      vector.add(new DERTaggedObject(true, 2, new DERUTF8String(label)));
    }

    return new DERSequence(vector);
  }

  public P11IdentityId getValue() {
    return value;
  }

} // class IdentityId
