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
 *     control              NewKeyControl OPTIONAL,
 *     p                    INTEGER,
 *     q                    INTEGER,
 *     g                    INTEGER}
 * </pre>
 *
 * @author Lijun Liao
 */
public class GenDSAKeypairParams extends ProxyMessage {

  private final P11SlotIdentifier slotId;

  private final P11NewKeyControl control;

  private final BigInteger p;

  private final BigInteger q;

  private final BigInteger g;

  public GenDSAKeypairParams(
      P11SlotIdentifier slotId, P11NewKeyControl control, BigInteger p, BigInteger q, BigInteger g) {
    this.slotId = Args.notNull(slotId, "slotId");
    this.control = control;
    this.p = Args.notNull(p, "p");
    this.q = Args.notNull(q, "q");
    this.g = Args.notNull(g, "g");
  }

  private GenDSAKeypairParams(ASN1Sequence seq) throws BadAsn1ObjectException {
    requireRange(seq, 4, 5);
    int idx = 0;
    slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++)).getValue();

    ASN1Primitive asn1 = seq.getObjectAt(idx++).toASN1Primitive();
    BigInteger bn = null;
    if (asn1 instanceof ASN1Sequence) {
      control = NewKeyControl.getInstance(asn1).getControl();
    } else {
      bn = getInteger(asn1);
      control = null;
    }

    if (control != null) {
      bn = getInteger(seq.getObjectAt(idx++));
    }

    p = bn;
    q = getInteger(seq.getObjectAt(idx++));
    g = getInteger(seq.getObjectAt(idx));
  }

  public static GenDSAKeypairParams getInstance(Object obj)
      throws BadAsn1ObjectException {
    if (obj == null || obj instanceof GenDSAKeypairParams) {
      return (GenDSAKeypairParams) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new GenDSAKeypairParams((ASN1Sequence) obj);
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
    if (control != null) {
      vector.add(new NewKeyControl(control));
    }
    vector.add(new ASN1Integer(p));
    vector.add(new ASN1Integer(q));
    vector.add(new ASN1Integer(g));
    return new DERSequence(vector);
  }

  public P11SlotIdentifier getSlotId() {
    return slotId;
  }

  public P11NewKeyControl getControl() {
    return control;
  }

  public BigInteger getP() {
    return p;
  }

  public BigInteger getQ() {
    return q;
  }

  public BigInteger getG() {
    return g;
  }

} // class GenDSAKeypairParams
