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
import java.util.LinkedList;
import java.util.List;

/**
 * List of {@link ObjectIdentifier}s.
 *
 * <pre>
 * P11ObjectIdentifiers ::= SEQUENCE OF P11ObjectIdentifier
 * </pre>
 *
 * @author Lijun Liao
 *
 */
public class ObjectIdentifiers extends ProxyMessage {

  private final List<ObjectIdentifier> objectIds;

  public ObjectIdentifiers(List<ObjectIdentifier> objectIds) {
    this.objectIds = Args.notNull(objectIds, "objectIds");
  }

  private ObjectIdentifiers(ASN1Sequence seq) throws BadAsn1ObjectException {
    this.objectIds = new LinkedList<>();
    final int size = seq.size();
    for (int i = 0; i < size; i++) {
      objectIds.add(ObjectIdentifier.getInstance(seq.getObjectAt(i)));
    }
  }

  public static ObjectIdentifiers getInstance(Object obj) throws BadAsn1ObjectException {
    if (obj == null || obj instanceof ObjectIdentifiers) {
      return (ObjectIdentifiers) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new ObjectIdentifiers((ASN1Sequence) obj);
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
    for (ObjectIdentifier objectId : objectIds) {
      vec.add(objectId);
    }
    return new DERSequence(vec);
  }

  public List<ObjectIdentifier> getObjectIds() {
    return objectIds;
  }

} // class ObjectIdentifiers
