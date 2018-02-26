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
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.BadAsn1ObjectException;
import org.xipki.security.pkcs11.P11EntityIdentifier;

/**
 * TODO.
 * <pre>
 * EntityIdAndCert ::= SEQUENCE {
 *     entityId             EntityIdentifer,
 *     certificate          Certificate }
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1EntityIdAndCert extends ASN1Object {

  private final Asn1P11EntityIdentifier entityId;

  private final Certificate certificate;

  public Asn1EntityIdAndCert(Asn1P11EntityIdentifier entityId, Certificate certificate) {
    this.entityId = ParamUtil.requireNonNull("entityId", entityId);
    this.certificate = ParamUtil.requireNonNull("certificate", certificate);
  }

  public Asn1EntityIdAndCert(P11EntityIdentifier entityId, X509Certificate certificate) {
    ParamUtil.requireNonNull("entityId", entityId);
    ParamUtil.requireNonNull("certificate", certificate);
    this.entityId = new Asn1P11EntityIdentifier(entityId);
    byte[] encoded;
    try {
      encoded = certificate.getEncoded();
    } catch (CertificateEncodingException ex) {
      throw new IllegalArgumentException("could not encode certificate: " + ex.getMessage(), ex);
    }
    this.certificate = Certificate.getInstance(encoded);
  }

  private Asn1EntityIdAndCert(ASN1Sequence seq) throws BadAsn1ObjectException {
    Asn1Util.requireRange(seq, 2, 2);
    int idx = 0;
    this.entityId = Asn1P11EntityIdentifier.getInstance(seq.getObjectAt(idx++));
    this.certificate = Asn1Util.getCertificate(seq.getObjectAt(idx++));
  }

  public static Asn1EntityIdAndCert getInstance(Object obj) throws BadAsn1ObjectException {
    if (obj == null || obj instanceof Asn1EntityIdAndCert) {
      return (Asn1EntityIdAndCert) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new Asn1EntityIdAndCert((ASN1Sequence) obj);
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
    vector.add(entityId);
    vector.add(certificate);
    return new DERSequence(vector);
  }

  public Asn1P11EntityIdentifier entityId() {
    return entityId;
  }

  public Certificate certificate() {
    return certificate;
  }

}
