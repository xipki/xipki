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
import org.xipki.security.pkcs11.P11RSAPkcsPssParams;

/**
* TODO.
* <pre>
* RSAPkcsPssParams ::= SEQUENCE {
*     contentHash       INTEGER,
*     mgfHash           INTEGER,
*     saltLength        INTEGER }
* </pre>
*
* @author Lijun Liao
* @since 2.0.0
*/

// CHECKSTYLE:SKIP
public class Asn1RSAPkcsPssParams extends ASN1Object {

  private final P11RSAPkcsPssParams pkcsPssParams;

  public Asn1RSAPkcsPssParams(P11RSAPkcsPssParams pkcsPssParams) {
    this.pkcsPssParams = ParamUtil.requireNonNull("pkcsPssParams", pkcsPssParams);
  }

  private Asn1RSAPkcsPssParams(ASN1Sequence seq) throws BadAsn1ObjectException {
    Asn1Util.requireRange(seq, 3, 3);
    int idx = 0;
    long contentHash = Asn1Util.getInteger(seq.getObjectAt(idx++)).longValue();
    long mgfHash = Asn1Util.getInteger(seq.getObjectAt(idx++)).longValue();
    int saltLength = Asn1Util.getInteger(seq.getObjectAt(idx++)).intValue();
    this.pkcsPssParams = new P11RSAPkcsPssParams(contentHash, mgfHash, saltLength);
  } // constructor

  public static Asn1RSAPkcsPssParams getInstance(Object obj) throws BadAsn1ObjectException {
    if (obj == null || obj instanceof Asn1RSAPkcsPssParams) {
      return (Asn1RSAPkcsPssParams) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new Asn1RSAPkcsPssParams((ASN1Sequence) obj);
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
    vector.add(new ASN1Integer(pkcsPssParams.hashAlgorithm()));
    vector.add(new ASN1Integer(pkcsPssParams.maskGenerationFunction()));
    vector.add(new ASN1Integer(pkcsPssParams.saltLength()));
    return new DERSequence(vector);
  }

  public P11RSAPkcsPssParams pkcsPssParams() {
    return pkcsPssParams;
  }

}
