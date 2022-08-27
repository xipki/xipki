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

package org.xipki.security.pkcs11.proxy;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.xipki.security.X509Cert;
import org.xipki.security.pkcs11.P11Identity;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11Params;
import org.xipki.security.pkcs11.P11Params.P11ByteArrayParams;
import org.xipki.security.pkcs11.P11Params.P11IVParams;
import org.xipki.security.pkcs11.P11Params.P11RSAPkcsPssParams;
import org.xipki.security.pkcs11.P11TokenException;
import org.xipki.security.pkcs11.proxy.asn1.DigestSecretKeyTemplate;
import org.xipki.security.pkcs11.proxy.asn1.ObjectIdentifier;
import org.xipki.security.pkcs11.proxy.asn1.RSAPkcsPssParams;
import org.xipki.security.pkcs11.proxy.asn1.SignTemplate;

import java.security.PublicKey;

/**
 * {@link P11Identity} for PKCS#11 proxy.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class ProxyP11Identity extends P11Identity {

  private final ObjectIdentifier asn1KeyId;

  ProxyP11Identity(ProxyP11Slot slot, P11IdentityId identityId) {
    super(slot, identityId, 0);
    this.asn1KeyId = new ObjectIdentifier(identityId.getKeyId());
  }

  ProxyP11Identity(ProxyP11Slot slot, P11IdentityId identityId, PublicKey publicKey, X509Cert[] certificateChain) {
    super(slot, identityId, publicKey, certificateChain);
    this.asn1KeyId = new ObjectIdentifier(identityId.getKeyId());
  }

  @Override
  protected byte[] sign0(long mechanism, P11Params parameters, byte[] content)
      throws P11TokenException {
    org.xipki.security.pkcs11.proxy.asn1.P11Params p11Param = null;
    if (parameters != null) {
      if (parameters instanceof P11RSAPkcsPssParams) {
        p11Param = new org.xipki.security.pkcs11.proxy.asn1.P11Params(
            org.xipki.security.pkcs11.proxy.asn1.P11Params.TAG_RSA_PKCS_PSS,
            new RSAPkcsPssParams((P11RSAPkcsPssParams) parameters));
      } else if (parameters instanceof P11ByteArrayParams) {
        byte[] bytes = ((P11ByteArrayParams) parameters).getBytes();
        p11Param = new org.xipki.security.pkcs11.proxy.asn1.P11Params(
            org.xipki.security.pkcs11.proxy.asn1.P11Params.TAG_OPAQUE,
            new DEROctetString(bytes));
      } else if (parameters instanceof P11IVParams) {
        p11Param = new org.xipki.security.pkcs11.proxy.asn1.P11Params(
            org.xipki.security.pkcs11.proxy.asn1.P11Params.TAG_IV,
            new DEROctetString(((P11IVParams) parameters).getIV()));
      } else {
        throw new IllegalArgumentException("unkown parameter 'parameters'");
      }
    }

    SignTemplate signTemplate = new SignTemplate(
        ((ProxyP11Slot) slot).getAsn1SlotId(), asn1KeyId, mechanism, p11Param, content);
    byte[] result = ((ProxyP11Slot) slot).getModule().send(P11ProxyConstants.ACTION_SIGN, signTemplate);

    ASN1OctetString octetString;
    try {
      octetString = DEROctetString.getInstance(result);
    } catch (IllegalArgumentException ex) {
      throw new P11TokenException("the returned result is not OCTET STRING");
    }

    return (octetString == null) ? null : octetString.getOctets();
  } // method sign0

  @Override
  protected byte[] digestSecretKey0(long mechanism) throws P11TokenException {
    DigestSecretKeyTemplate template =
        new DigestSecretKeyTemplate(((ProxyP11Slot) slot).getAsn1SlotId(), asn1KeyId, mechanism);
    byte[] result = ((ProxyP11Slot) slot).getModule().send(P11ProxyConstants.ACTION_DIGEST_SECRETKEY, template);

    ASN1OctetString octetString;
    try {
      octetString = DEROctetString.getInstance(result);
    } catch (IllegalArgumentException ex) {
      throw new P11TokenException("the returned result is not OCTET STRING");
    }

    return (octetString == null) ? null : octetString.getOctets();
  } // method digestSecretKey0

}
