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
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.util.Args;

import java.io.IOException;

/**
 * Slot identifier.
 *
 * <pre>
 * SlotIdentifier ::= SEQUENCE {
 *     id         INTEGER,
 *     index      INTEGER }
 * </pre>
 *
 * @author Lijun Liao
 */
public class SlotIdentifier extends ProxyMessage {

  private final P11SlotIdentifier value;

  public SlotIdentifier(P11SlotIdentifier value) {
    this.value = Args.notNull(value, "value");
  }

  private SlotIdentifier(ASN1Sequence seq) throws BadAsn1ObjectException {
    requireRange(seq, 2, 2);
    long id = getInteger(seq.getObjectAt(0)).longValue();
    int index = getInteger(seq.getObjectAt(1)).intValue();
    this.value = new P11SlotIdentifier(index, id);
  }

  public static SlotIdentifier getInstance(Object obj) throws BadAsn1ObjectException {
    if (obj == null || obj instanceof SlotIdentifier) {
      return (SlotIdentifier) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new SlotIdentifier((ASN1Sequence) obj);
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
    vector.add(new ASN1Integer(value.getId()));
    vector.add(new ASN1Integer(value.getIndex()));
    return new DERSequence(vector);
  }

  public P11SlotIdentifier getValue() {
    return value;
  }

} // class SlotIdentifier
