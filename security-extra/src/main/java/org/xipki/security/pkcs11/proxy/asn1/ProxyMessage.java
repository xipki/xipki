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
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.security.BadAsn1ObjectException;

import java.math.BigInteger;

/**
 * ASN.1 Messages communicated between the PKCS#11 proxy client and server.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
public abstract class ProxyMessage extends ASN1Object {

  protected static void requireRange(ASN1Sequence seq, int minSize, int maxSize)
      throws BadAsn1ObjectException {
    int size = seq.size();
    if (size < minSize || size > maxSize) {
      String msg = String.format("seq.size() must not be out of the range [%d, %d]: %d", minSize, maxSize, size);
      throw new BadAsn1ObjectException(msg);
    }
  }

  protected static Certificate getCertificate0(ASN1Encodable object)
      throws BadAsn1ObjectException {
    try {
      return Certificate.getInstance(object);
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object Certificate: " + ex.getMessage(), ex);
    }
  }

  protected static BigInteger getInteger(ASN1Encodable object)
      throws BadAsn1ObjectException {
    try {
      return ASN1Integer.getInstance(object).getValue();
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object ASN1Integer: " + ex.getMessage(), ex);
    }
  }

  protected static String getUtf8String(ASN1Encodable object)
      throws BadAsn1ObjectException {
    try {
      return ASN1UTF8String.getInstance(object).getString();
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object UTF8String: " + ex.getMessage(), ex);
    }
  }

  protected static byte[] getOctetStringBytes(ASN1Encodable object)
      throws BadAsn1ObjectException {
    try {
      return DEROctetString.getInstance(object).getOctets();
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object OctetString: " + ex.getMessage(), ex);
    }
  }

  protected static ASN1ObjectIdentifier getObjectIdentifier(ASN1Encodable object)
      throws BadAsn1ObjectException {
    try {
      return ASN1ObjectIdentifier.getInstance(object);
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object ObjectIdentifier: " + ex.getMessage(), ex);
    }
  }

}

