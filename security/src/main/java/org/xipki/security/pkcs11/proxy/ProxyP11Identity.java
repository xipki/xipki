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

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.xipki.security.pkcs11.P11Identity;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11Params;
import org.xipki.security.pkcs11.P11Params.P11ByteArrayParams;
import org.xipki.security.pkcs11.P11Params.P11IVParams;
import org.xipki.security.pkcs11.P11Params.P11RSAPkcsPssParams;
import org.xipki.security.pkcs11.P11TokenException;

/**
 * {@link P11Identity} for PKCS#11 proxy.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class ProxyP11Identity extends P11Identity {

  private final ProxyMessage.ObjectIdentifier asn1KeyId;

  ProxyP11Identity(ProxyP11Slot slot, P11IdentityId identityId) {
    super(slot, identityId, 0);
    this.asn1KeyId = new ProxyMessage.ObjectIdentifier(identityId.getKeyId());
  }

  ProxyP11Identity(ProxyP11Slot slot, P11IdentityId identityId, PublicKey publicKey,
      X509Certificate[] certificateChain) {
    super(slot, identityId, publicKey, certificateChain);
    this.asn1KeyId = new ProxyMessage.ObjectIdentifier(identityId.getKeyId());
  }

  @Override
  protected byte[] sign0(long mechanism, P11Params parameters, byte[] content)
      throws P11TokenException {
    ProxyMessage.P11Params p11Param = null;
    if (parameters != null) {
      if (parameters instanceof P11RSAPkcsPssParams) {
        p11Param = new ProxyMessage.P11Params(ProxyMessage.P11Params.TAG_RSA_PKCS_PSS,
            new ProxyMessage.RSAPkcsPssParams((P11RSAPkcsPssParams) parameters));
      } else if (parameters instanceof P11ByteArrayParams) {
        byte[] bytes = ((P11ByteArrayParams) parameters).getBytes();
        p11Param = new ProxyMessage.P11Params(ProxyMessage.P11Params.TAG_OPAQUE,
            new DEROctetString(bytes));
      } else if (parameters instanceof P11IVParams) {
        p11Param = new ProxyMessage.P11Params(ProxyMessage.P11Params.TAG_IV,
            new DEROctetString(((P11IVParams) parameters).getIV()));
      } else {
        throw new IllegalArgumentException("unkown parameter 'parameters'");
      }
    }

    ProxyMessage.SignTemplate signTemplate = new ProxyMessage.SignTemplate(
        ((ProxyP11Slot) slot).getAsn1SlotId(), asn1KeyId, mechanism, p11Param, content);
    byte[] result = ((ProxyP11Slot) slot).getModule().send(P11ProxyConstants.ACTION_SIGN,
        signTemplate);

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
    ProxyMessage.DigestSecretKeyTemplate template =
        new ProxyMessage.DigestSecretKeyTemplate(
            ((ProxyP11Slot) slot).getAsn1SlotId(), asn1KeyId, mechanism);
    byte[] result = ((ProxyP11Slot) slot).getModule().send(
        P11ProxyConstants.ACTION_DIGEST_SECRETKEY, template);

    ASN1OctetString octetString;
    try {
      octetString = DEROctetString.getInstance(result);
    } catch (IllegalArgumentException ex) {
      throw new P11TokenException("the returned result is not OCTET STRING");
    }

    return (octetString == null) ? null : octetString.getOctets();
  } // method digestSecretKey0

}
