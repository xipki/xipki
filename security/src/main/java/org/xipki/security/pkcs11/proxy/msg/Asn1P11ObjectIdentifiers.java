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
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.BadAsn1ObjectException;

/**
 * TODO.
 * <pre>
 * P11ObjectIdentifiers ::= SEQUENCE OF P11ObjectIdentifier
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1P11ObjectIdentifiers extends ASN1Object {

  private final List<Asn1P11ObjectIdentifier> objectIds;

  public Asn1P11ObjectIdentifiers(List<Asn1P11ObjectIdentifier> objectIds) {
    this.objectIds = ParamUtil.requireNonNull("objectIds", objectIds);
  }

  private Asn1P11ObjectIdentifiers(ASN1Sequence seq) throws BadAsn1ObjectException {
    this.objectIds = new LinkedList<>();
    final int size = seq.size();
    for (int i = 0; i < size; i++) {
      objectIds.add(Asn1P11ObjectIdentifier.getInstance(seq.getObjectAt(i)));
    }
  }

  public static Asn1P11ObjectIdentifiers getInstance(Object obj) throws BadAsn1ObjectException {
    if (obj == null || obj instanceof Asn1P11ObjectIdentifiers) {
      return (Asn1P11ObjectIdentifiers) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new Asn1P11ObjectIdentifiers((ASN1Sequence) obj);
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
    ASN1EncodableVector vec = new ASN1EncodableVector();
    for (Asn1P11ObjectIdentifier objectId : objectIds) {
      vec.add(objectId);
    }
    return new DERSequence(vec);
  }

  public List<Asn1P11ObjectIdentifier> objectIds() {
    return objectIds;
  }

}
