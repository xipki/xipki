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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.xipki.security.BadAsn1ObjectException;
import org.xipki.util.Args;

import java.io.IOException;

/**
 * ASN.1 PKCS#11 params.
 *
 * <pre>
 * P11Params ::= CHOICE {
 *     rsaPkcsPssParams   [0]  RSA-PKCS-PSS-Parameters,
 *     opaqueParams       [1]  OCTET-STRING,
 *     iv                 [2]  IV }
 * </pre>
 *
 * @author Lijun Liao
 */
public class P11Params extends ProxyMessage {

  public static final int TAG_RSA_PKCS_PSS = 0;

  public static final int TAG_OPAQUE = 1;

  public static final int TAG_IV = 2;

  private final int tagNo;
  private final ASN1Encodable p11Params;

  public P11Params(int tagNo, ASN1Encodable p11Params) {
    this.tagNo = tagNo;
    this.p11Params = Args.notNull(p11Params, "p11Params");
  }

  private P11Params(ASN1TaggedObject taggedObject) {
    this.tagNo = taggedObject.getTagNo();
    this.p11Params = taggedObject.getBaseObject();
  }

  public static P11Params getInstance(Object obj) throws BadAsn1ObjectException {
    if (obj == null || obj instanceof P11Params) {
      return (P11Params) obj;
    }

    try {
      if (obj instanceof ASN1TaggedObject) {
        return new P11Params((ASN1TaggedObject) obj);
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
    return new DERTaggedObject(tagNo, p11Params);
  }

  public int getTagNo() {
    return tagNo;
  }

  public ASN1Encodable getP11Params() {
    return p11Params;
  }

} // class P11Params
