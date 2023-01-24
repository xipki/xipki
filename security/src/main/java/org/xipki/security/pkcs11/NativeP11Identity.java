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

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.math.ec.ECCurve;
import org.xipki.security.EdECConstants;

import java.math.BigInteger;

/**
 * {@link P11Identity} based on the ipkcs11wrapper or jpkcs11wrapper.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class NativeP11Identity extends P11Identity {

  NativeP11Identity(NativeP11Slot slot, P11IdentityId identityId) {
    super(slot, identityId);
  }

  @Override
  protected byte[] digestSecretKey0(long mechanism) throws P11TokenException {
    return ((NativeP11Slot) slot).digestSecretKey(mechanism, this);
  }

  @Override
  public void destroy() throws P11TokenException {
    if (id.getPublicKeyHandle() == null) {
      slot.destroyObjects(id.getKeyId().getHandle());
    } else {
      slot.destroyObjects(id.getKeyId().getHandle(), id.getPublicKeyHandle());
    }
  }

  @Override
  protected byte[] sign0(long mechanism, P11Params parameters, byte[] content) throws P11TokenException {
    return ((NativeP11Slot) slot).sign(mechanism, parameters, content, this);
  }

}
