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

/**
 * Parameters to generate secret key.
 *
 * <pre>
 * GenSecretKeyParams ::= SEQUENCE {
 *     slotId               P11SlotIdentifier,
 *     control              NewKeyControl,
 *     keyType              INTEGER,
 *     keysize              INTEGER }
 * </pre>
 *
 * @author Lijun Liao
 */
public class GenSecretKeyParams extends ProxyMessage {

  private final P11SlotIdentifier slotId;

  private final P11NewKeyControl control;

  private final long keyType;

  private final int keysize;

  public GenSecretKeyParams(P11SlotIdentifier slotId, P11NewKeyControl control, long keyType, int keysize) {
    this.slotId = Args.notNull(slotId, "slotId");
    this.control = Args.notNull(control, "control");
    this.keyType = keyType;
    this.keysize = Args.min(keysize, "keysize", 1);
  }

  private GenSecretKeyParams(ASN1Sequence seq) throws BadAsn1ObjectException {
    requireRange(seq, 4, 4);
    int idx = 0;
    slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++)).getValue();
    control = NewKeyControl.getInstance(seq.getObjectAt(idx++)).getControl();
    keyType = getInteger(seq.getObjectAt(idx++)).longValue();
    keysize = getInteger(seq.getObjectAt(idx)).intValue();
    Args.min(keysize, "keysize", 1);
  }

  public static GenSecretKeyParams getInstance(Object obj) throws BadAsn1ObjectException {
    if (obj == null || obj instanceof GenSecretKeyParams) {
      return (GenSecretKeyParams) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new GenSecretKeyParams((ASN1Sequence) obj);
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
    vector.add(new ASN1Integer(keyType));
    vector.add(new ASN1Integer(keysize));
    return new DERSequence(vector);
  }

  public P11SlotIdentifier getSlotId() {
    return slotId;
  }

  public P11NewKeyControl getControl() {
    return control;
  }

  public long getKeyType() {
    return keyType;
  }

  public int getKeysize() {
    return keysize;
  }

} // class GenSecretKeyParams
