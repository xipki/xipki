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

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.security.exception.BadAsn1ObjectException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1Util {

  private Asn1Util() {
  }

  public static void requireRange(ASN1Sequence seq, int minSize, int maxSize)
      throws BadAsn1ObjectException {
    int size = seq.size();
    if (size < minSize || size > maxSize) {
      String msg = String.format("seq.size() must not be out of the range [%d, %d]: %d",
          minSize, maxSize, size);
      throw new IllegalArgumentException(msg);
    }
  }

  public static ASN1Sequence getSequence(ASN1Encodable object) throws BadAsn1ObjectException {
    try {
      return ASN1Sequence.getInstance(object);
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object Sequence: " + ex.getMessage(), ex);
    }
  }

  public static Certificate getCertificate(ASN1Encodable object) throws BadAsn1ObjectException {
    try {
      return Certificate.getInstance(object);
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object Certificate: " + ex.getMessage(), ex);
    }
  }

  public static BigInteger getInteger(ASN1Encodable object) throws BadAsn1ObjectException {
    try {
      return ASN1Integer.getInstance(object).getValue();
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object ASN1Integer: " + ex.getMessage(), ex);
    }
  }

  public static String getUtf8String(ASN1Encodable object) throws BadAsn1ObjectException {
    try {
      return DERUTF8String.getInstance(object).getString();
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object UTF8String: " + ex.getMessage(), ex);
    }
  }

  public static byte[] getOctetStringBytes(ASN1Encodable object) throws BadAsn1ObjectException {
    try {
      return DEROctetString.getInstance(object).getOctets();
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object OctetString: " + ex.getMessage(), ex);
    }
  }

  public static ASN1ObjectIdentifier getObjectIdentifier(ASN1Encodable object)
      throws BadAsn1ObjectException {
    try {
      return ASN1ObjectIdentifier.getInstance(object);
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object ObjectIdentifier: " + ex.getMessage(), ex);
    }
  }

}
