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
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.util.Args;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Parameters to generate RSA keypair.
 *
 * <pre>
 * GenRSAKeypairParams ::= SEQUENCE {
 *     slotId               P11SlotIdentifier,
 *     control              NewKeyControl,
 *     keysize              INTEGER,
 *     publicExponent       INTEGER OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao
 */
// CHECKSTYLE:SKIP
public class GenRSAKeypairParams extends ProxyMessage {

  private final P11SlotIdentifier slotId;

  private final P11NewKeyControl control;

  private final int keysize;

  private final BigInteger publicExponent;

  public GenRSAKeypairParams(P11SlotIdentifier slotId,
      P11NewKeyControl control, int keysize, BigInteger publicExponent) {
    this.slotId = Args.notNull(slotId, "slotId");
    this.control = Args.notNull(control, "control");
    this.keysize = Args.min(keysize, "keysize", 1);
    this.publicExponent = publicExponent;
  }

  private GenRSAKeypairParams(ASN1Sequence seq)
      throws BadAsn1ObjectException {
    requireRange(seq, 3, 4);
    final int size = seq.size();
    int idx = 0;
    slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++)).getValue();
    control = NewKeyControl.getInstance(seq.getObjectAt(idx++)).getControl();
    keysize = getInteger(seq.getObjectAt(idx++)).intValue();
    Args.min(keysize, "keysize", 1);

    publicExponent = (size > 3) ? getInteger(seq.getObjectAt(idx++)) : null;
  }

  public static GenRSAKeypairParams getInstance(Object obj)
      throws BadAsn1ObjectException {
    if (obj == null || obj instanceof GenRSAKeypairParams) {
      return (GenRSAKeypairParams) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new GenRSAKeypairParams((ASN1Sequence) obj);
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
    vector.add(new SlotIdentifier(slotId));
    vector.add(new NewKeyControl(control));
    vector.add(new ASN1Integer(keysize));
    if (publicExponent != null) {
      vector.add(new ASN1Integer(publicExponent));
    }
    return new DERSequence(vector);
  }

  public P11SlotIdentifier getSlotId() {
    return slotId;
  }

  public P11NewKeyControl getControl() {
    return control;
  }

  public int getKeysize() {
    return keysize;
  }

  public BigInteger getPublicExponent() {
    return publicExponent;
  }

} // class GenRSAKeypairParams
