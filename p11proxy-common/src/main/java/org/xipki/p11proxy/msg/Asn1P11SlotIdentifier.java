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
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.BadAsn1ObjectException;
import org.xipki.security.pkcs11.P11SlotIdentifier;

/**
 * TODO.
 * <pre>
 * SlotIdentifier ::= SEQUENCE {
 *     id         INTEGER,
 *     index      INTEGER }
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1P11SlotIdentifier extends ASN1Object {

  private final P11SlotIdentifier slotId;

  public Asn1P11SlotIdentifier(P11SlotIdentifier slotId) {
    this.slotId = ParamUtil.requireNonNull("slotId", slotId);
  }

  private Asn1P11SlotIdentifier(ASN1Sequence seq) throws BadAsn1ObjectException {
    Asn1Util.requireRange(seq, 2, 2);
    int idx = 0;
    long id = Asn1Util.getInteger(seq.getObjectAt(idx++)).longValue();
    int index = Asn1Util.getInteger(seq.getObjectAt(idx++)).intValue();
    this.slotId = new P11SlotIdentifier(index, id);
  }

  public static Asn1P11SlotIdentifier getInstance(Object obj) throws BadAsn1ObjectException {
    if (obj == null || obj instanceof Asn1P11SlotIdentifier) {
      return (Asn1P11SlotIdentifier) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new Asn1P11SlotIdentifier((ASN1Sequence) obj);
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
    vector.add(new ASN1Integer(slotId.id()));
    vector.add(new ASN1Integer(slotId.index()));
    return new DERSequence(vector);
  }

  public P11SlotIdentifier slotId() {
    return slotId;
  }

}
