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
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.util.Args;

import java.io.IOException;

/**
 * Identifier of PKCS#11 object.
 *
 * <pre>
 * P11ObjectIdentifier ::= SEQUENCE {
 *     id        OCTET STRING,
 *     label     UTF8STRING }
 * </pre>
 *
 * @author Lijun Liao
 */
public class ObjectIdentifier extends ProxyMessage {

  private final P11ObjectIdentifier value;

  public ObjectIdentifier(P11ObjectIdentifier value) {
    this.value = Args.notNull(value, "value");
  }

  private ObjectIdentifier(ASN1Sequence seq)
      throws BadAsn1ObjectException {
    requireRange(seq, 2, 2);
    int idx = 0;
    byte[] id = getOctetStringBytes(seq.getObjectAt(idx++));
    String label = getUtf8String(seq.getObjectAt(idx++));
    this.value = new P11ObjectIdentifier(id, label);
  }

  public static ObjectIdentifier getInstance(Object obj)
      throws BadAsn1ObjectException {
    if (obj == null || obj instanceof ObjectIdentifier) {
      return (ObjectIdentifier) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new ObjectIdentifier((ASN1Sequence) obj);
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
    vec.add(new DEROctetString(value.getId()));
    vec.add(new DERUTF8String(value.getLabel()));
    return new DERSequence(vec);
  }

  public P11ObjectIdentifier getValue() {
    return value;
  }

} // class ObjectIdentifier
