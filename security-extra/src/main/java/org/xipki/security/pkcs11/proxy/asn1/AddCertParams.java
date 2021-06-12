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
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.security.BadAsn1ObjectException;
import org.xipki.security.X509Cert;
import org.xipki.security.pkcs11.P11Slot.P11NewObjectControl;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.util.Args;

import java.io.IOException;

/**
 * Parameters to add certificate.
 *
 * <pre>
 * AddCertParams ::= SEQUENCE {
 *     slotId               P11SlotIdentifier,
 *     control              NewKeyControl,
 *     certificate          Certificate }
 * </pre>
 *
 * @author Lijun Liao
 */
public class AddCertParams extends ProxyMessage {

  private final P11SlotIdentifier slotId;

  private final P11NewObjectControl control;

  private final Certificate certificate;

  public AddCertParams(P11SlotIdentifier slotId, P11NewObjectControl control,
      Certificate certificate) {
    this.slotId = Args.notNull(slotId, "slotId");
    this.control = Args.notNull(control, "control");
    this.certificate = Args.notNull(certificate, "certificate");
  }

  public AddCertParams(P11SlotIdentifier slotId, P11NewObjectControl control,
      X509Cert certificate) {
    this.slotId = Args.notNull(slotId, "slotId");
    this.control = Args.notNull(control, "control");
    Args.notNull(certificate, "certificate");
    this.certificate = certificate.toBcCert().toASN1Structure();
  }

  private AddCertParams(ASN1Sequence seq)
      throws BadAsn1ObjectException {
    requireRange(seq, 3, 3);
    int idx = 0;
    slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++)).getValue();
    control = NewKeyControl.getInstance(seq.getObjectAt(idx++)).getControl();
    this.certificate = getCertificate0(seq.getObjectAt(idx++));
  }

  public static AddCertParams getInstance(Object obj)
      throws BadAsn1ObjectException {
    if (obj == null || obj instanceof AddCertParams) {
      return (AddCertParams) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new AddCertParams((ASN1Sequence) obj);
      } else if (obj instanceof byte[]) {
        return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
      } else {
        throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
      }
    } catch (IOException | IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("unable to parse object: " + ex.getMessage(), ex);
    }
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    vector.add(new SlotIdentifier(slotId));
    vector.add(new NewObjectControl(control));
    vector.add(certificate);
    return new DERSequence(vector);
  }

  public P11SlotIdentifier getSlotId() {
    return slotId;
  }

  public P11NewObjectControl getControl() {
    return control;
  }

  public Certificate getCertificate() {
    return certificate;
  }

} // class AddCertParams
