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

package org.xipki.security.pkcs11.proxy;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.xipki.p11proxy.P11ProxyConstants;
import org.xipki.p11proxy.msg.Asn1DigestSecretKeyTemplate;
import org.xipki.p11proxy.msg.Asn1P11EntityIdentifier;
import org.xipki.p11proxy.msg.Asn1P11Params;
import org.xipki.p11proxy.msg.Asn1RSAPkcsPssParams;
import org.xipki.p11proxy.msg.Asn1SignTemplate;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.pkcs11.P11ByteArrayParams;
import org.xipki.security.pkcs11.P11EntityIdentifier;
import org.xipki.security.pkcs11.P11IVParams;
import org.xipki.security.pkcs11.P11Identity;
import org.xipki.security.pkcs11.P11Params;
import org.xipki.security.pkcs11.P11RSAPkcsPssParams;
import org.xipki.security.pkcs11.P11Slot;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class ProxyP11Identity extends P11Identity {

  ProxyP11Identity(P11Slot slot, P11EntityIdentifier entityId) {
    super(slot, entityId, 0);
  }

  ProxyP11Identity(P11Slot slot, P11EntityIdentifier entityId, PublicKey publicKey,
      X509Certificate[] certificateChain) {
    super(slot, entityId, publicKey, certificateChain);
  }

  @Override
  protected byte[] sign0(long mechanism, P11Params parameters, byte[] content)
      throws P11TokenException {
    Asn1P11EntityIdentifier asn1EntityId = new Asn1P11EntityIdentifier(identityId);
    Asn1P11Params p11Param = null;
    if (parameters != null) {
      if (parameters instanceof P11RSAPkcsPssParams) {
        p11Param = new Asn1P11Params(Asn1P11Params.TAG_RSA_PKCS_PSS,
            new Asn1RSAPkcsPssParams((P11RSAPkcsPssParams) parameters));
      } else if (parameters instanceof P11ByteArrayParams) {
        byte[] bytes = ((P11ByteArrayParams) parameters).getBytes();
        p11Param = new Asn1P11Params(Asn1P11Params.TAG_OPAQUE, new DEROctetString(bytes));
      } else if (parameters instanceof P11IVParams) {
        p11Param = new Asn1P11Params(Asn1P11Params.TAG_IV,
            new DEROctetString(((P11IVParams) parameters).getIV()));
      } else {
        throw new IllegalArgumentException("unkown parameter 'parameters'");
      }
    }

    Asn1SignTemplate signTemplate = new Asn1SignTemplate(asn1EntityId, mechanism, p11Param,
        content);
    byte[] result = ((ProxyP11Slot) slot).getModule().send(P11ProxyConstants.ACTION_SIGN,
        signTemplate);

    ASN1OctetString octetString;
    try {
      octetString = DEROctetString.getInstance(result);
    } catch (IllegalArgumentException ex) {
      throw new P11TokenException("the returned result is not OCTET STRING");
    }

    return (octetString == null) ? null : octetString.getOctets();
  }

  @Override
  protected byte[] digestSecretKey0(long mechanism) throws P11TokenException {
    Asn1P11EntityIdentifier asn1EntityId = new Asn1P11EntityIdentifier(identityId);
    Asn1DigestSecretKeyTemplate template = new Asn1DigestSecretKeyTemplate(asn1EntityId, mechanism);
    byte[] result = ((ProxyP11Slot) slot).getModule().send(
        P11ProxyConstants.ACTION_DIGEST_SECRETKEY, template);

    ASN1OctetString octetString;
    try {
      octetString = DEROctetString.getInstance(result);
    } catch (IllegalArgumentException ex) {
      throw new P11TokenException("the returned result is not OCTET STRING");
    }

    return (octetString == null) ? null : octetString.getOctets();
  }

}
