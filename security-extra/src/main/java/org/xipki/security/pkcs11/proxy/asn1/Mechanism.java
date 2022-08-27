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

import java.io.IOException;

/**
 * Definition of Mechanism.
 *
 * <pre>
 * Mechanism ::= SEQUENCE {
 *     mechanism     INTEGER,
 *     params        P11Params OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao
 */
public class Mechanism extends ProxyMessage {

  private final long mechanism;

  private final P11Params params;

  public Mechanism(long mechanism, P11Params params) {
    this.mechanism = mechanism;
    this.params = params;
  }

  private Mechanism(ASN1Sequence seq) throws BadAsn1ObjectException {
    requireRange(seq, 1, 2);
    int size = seq.size();
    this.mechanism = getInteger(seq.getObjectAt(0)).longValue();
    this.params = (size > 1)  ? P11Params.getInstance(seq.getObjectAt(1)) : null;
  }

  public static Mechanism getInstance(Object obj) throws BadAsn1ObjectException {
    if (obj == null || obj instanceof Mechanism) {
      return (Mechanism) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new Mechanism((ASN1Sequence) obj);
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
    vector.add(new ASN1Integer(mechanism));
    if (params != null) {
      vector.add(params);
    }
    return new DERSequence(vector);
  }

  public long getMechanism() {
    return mechanism;
  }

  public P11Params getParams() {
    return params;
  }

} // method Mechanism
