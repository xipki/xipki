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
import org.bouncycastle.util.Arrays;
import org.xipki.security.BadAsn1ObjectException;
import org.xipki.security.pkcs11.P11Slot.P11NewKeyControl;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.util.Args;

import java.io.IOException;

/**
 * Parameters to import secret key.
 *
 * <pre>
 * ImportSecretKeyParams ::= SEQUENCE {
 *     slotId               P11SlotIdentifier,
 *     control              NewKeyControl,
 *     keyType              INTEGER,
 *     keyValue             OCTET STRING}
 * </pre>
 *
 * @author Lijun Liao
 */
// CHECKSTYLE:SKIP
public class ImportSecretKeyParams extends ProxyMessage {

  private final P11SlotIdentifier slotId;

  private final P11NewKeyControl control;

  private final long keyType;

  private final byte[] keyValue;

  public ImportSecretKeyParams(P11SlotIdentifier slotId,
      P11NewKeyControl control, long keyType, byte[] keyValue) {
    this.slotId = Args.notNull(slotId, "slotId");
    this.control = Args.notNull(control, "control");
    this.keyType = keyType;
    this.keyValue = Args.notNull(keyValue, "keyValue");
  }

  private ImportSecretKeyParams(ASN1Sequence seq)
      throws BadAsn1ObjectException {
    requireRange(seq, 4, 4);
    int idx = 0;
    slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++)).getValue();
    control = NewKeyControl.getInstance(seq.getObjectAt(idx++)).getControl();
    keyType = getInteger(seq.getObjectAt(idx++)).longValue();
    keyValue = ASN1OctetString.getInstance(seq.getObjectAt(idx++)).getOctets();
  }

  public static ImportSecretKeyParams getInstance(Object obj)
      throws BadAsn1ObjectException {
    if (obj == null || obj instanceof ImportSecretKeyParams) {
      return (ImportSecretKeyParams) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new ImportSecretKeyParams((ASN1Sequence) obj);
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
    vector.add(new ASN1Integer(keyType));
    vector.add(new DEROctetString(keyValue));
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

  public byte[] getKeyValue() {
    return Arrays.copyOf(keyValue, keyValue.length);
  }

} // method ImportSecretKeyParams
