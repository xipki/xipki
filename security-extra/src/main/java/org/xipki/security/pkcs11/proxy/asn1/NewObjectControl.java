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
import org.xipki.security.pkcs11.P11Slot.P11NewKeyControl;
import org.xipki.security.pkcs11.P11Slot.P11NewObjectControl;
import org.xipki.util.Args;

import java.io.IOException;

/**
 * Control how to create new PKCS#11 object.
 *
 * <pre>
 * NewKeyControl ::= SEQUENCE {
 *     label                  UTF8 STRING,
 *     id                 [0] OCTET STRING OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao
 */
public class NewObjectControl extends ProxyMessage {

  private final P11NewObjectControl control;

  public NewObjectControl(P11NewObjectControl control) {
    this.control = Args.notNull(control, "control");
  }

  private NewObjectControl(ASN1Sequence seq) {
    final int size = seq.size();
    Args.min(size, "seq.size", 1);
    String label = ASN1UTF8String.getInstance(seq.getObjectAt(0)).getString();
    byte[] id = null;

    for (int i = 1; i < size; i++) {
      ASN1Encodable obj = seq.getObjectAt(i);
      if (!(obj instanceof ASN1TaggedObject)) {
        continue;
      }

      ASN1TaggedObject tagObj = (ASN1TaggedObject) obj;
      int tagNo = tagObj.getTagNo();
      if (tagNo == 0) {
        id = DEROctetString.getInstance(tagObj.getBaseObject()).getOctets();
      }
    }

    this.control = new P11NewKeyControl(id, label);
  }

  public static NewObjectControl getInstance(Object obj) throws BadAsn1ObjectException {
    if (obj == null || obj instanceof NewObjectControl) {
      return (NewObjectControl) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new NewObjectControl((ASN1Sequence) obj);
      } else if (obj instanceof byte[]) {
        return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
      } else {
        throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
      }
    } catch (IOException | IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("unable to parse object: " + ex.getMessage(), ex);
    }
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    vector.add(new DERUTF8String(control.getLabel()));

    byte[] id = control.getId();
    if (id != null) {
      vector.add(new DERTaggedObject(0, new DEROctetString(id)));
    }

    return new DERSequence(vector);
  }

  public P11NewObjectControl getControl() {
    return control;
  }

} // class NewObjectControl
