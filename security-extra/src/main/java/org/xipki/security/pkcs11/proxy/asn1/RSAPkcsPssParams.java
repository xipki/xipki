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
import org.xipki.security.pkcs11.P11Params.P11RSAPkcsPssParams;
import org.xipki.util.Args;

import java.io.IOException;

/**
 * Parameters to create RSAPkcsPss signature.
 *
 * <pre>
 * RSAPkcsPssParams ::= SEQUENCE {
 *     contentHash       INTEGER,
 *     mgfHash           INTEGER,
 *     saltLength        INTEGER }
 * </pre>
 *
 * @author Lijun Liao
 */
public class RSAPkcsPssParams extends ProxyMessage {

  private final P11RSAPkcsPssParams pkcsPssParams;

  public RSAPkcsPssParams(P11RSAPkcsPssParams pkcsPssParams) {
    this.pkcsPssParams = Args.notNull(pkcsPssParams, "pkcsPssParams");
  }

  private RSAPkcsPssParams(ASN1Sequence seq) throws BadAsn1ObjectException {
    requireRange(seq, 3, 3);
    long contentHash = getInteger(seq.getObjectAt(0)).longValue();
    long mgfHash = getInteger(seq.getObjectAt(1)).longValue();
    int saltLength = getInteger(seq.getObjectAt(2)).intValue();
    this.pkcsPssParams = new P11RSAPkcsPssParams(contentHash, mgfHash, saltLength);
  } // constructor

  public static RSAPkcsPssParams getInstance(Object obj) throws BadAsn1ObjectException {
    if (obj == null || obj instanceof RSAPkcsPssParams) {
      return (RSAPkcsPssParams) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new RSAPkcsPssParams((ASN1Sequence) obj);
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
    vector.add(new ASN1Integer(pkcsPssParams.getHashAlgorithm()));
    vector.add(new ASN1Integer(pkcsPssParams.getMaskGenerationFunction()));
    vector.add(new ASN1Integer(pkcsPssParams.getSaltLength()));
    return new DERSequence(vector);
  }

  public P11RSAPkcsPssParams getPkcsPssParams() {
    return pkcsPssParams;
  }

} // class RSAPkcsPssParams
