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

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.BadAsn1ObjectException;
import org.xipki.security.pkcs11.P11NewKeyControl;

/**
 * TODO.
 * <pre>
 * NewKeyControl ::= SEQUENCE {
 *     extractable        [0] EXPLICIT BOOLEAN OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.2.0
 */

public class Asn1NewKeyControl extends ASN1Object {

  private final P11NewKeyControl control;

  public Asn1NewKeyControl(P11NewKeyControl control) {
    this.control = ParamUtil.requireNonNull("control", control);
  }

  private Asn1NewKeyControl(ASN1Sequence seq) throws BadAsn1ObjectException {
    control = new P11NewKeyControl();
    final int size = seq.size();
    for (int i = 0; i < size; i++) {
      ASN1Encodable obj = seq.getObjectAt(i);
      if (obj instanceof ASN1TaggedObject) {
        continue;
      }

      ASN1TaggedObject tagObj = (ASN1TaggedObject) obj;
      int tagNo = tagObj.getTagNo();
      if (tagNo == 0) {
        boolean bv = ((ASN1Boolean) tagObj.getObject()).isTrue();
        control.setExtractable(bv);
      }
    }
  }

  public static Asn1NewKeyControl getInstance(Object obj) throws BadAsn1ObjectException {
    if (obj == null || obj instanceof Asn1NewKeyControl) {
      return (Asn1NewKeyControl) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new Asn1NewKeyControl((ASN1Sequence) obj);
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
    vector.add(new DERTaggedObject(0, ASN1Boolean.getInstance(control.isExtractable())));
    return new DERSequence(vector);
  }

  public P11NewKeyControl getControl() {
    return control;
  }

}
