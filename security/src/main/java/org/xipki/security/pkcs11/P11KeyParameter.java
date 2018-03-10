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

package org.xipki.security.pkcs11;

import java.security.InvalidKeyException;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.xipki.common.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11KeyParameter extends AsymmetricKeyParameter {

  private final P11CryptService p11CryptService;

  private final P11SlotIdentifier slot;

  private final P11ObjectIdentifier objectId;

  private P11KeyParameter(P11CryptService p11CryptService, P11SlotIdentifier slot,
      P11ObjectIdentifier objectId) {
    super(true);

    this.p11CryptService = ParamUtil.requireNonNull("p11CryptService", p11CryptService);
    this.slot = ParamUtil.requireNonNull("slot", slot);
    this.objectId = ParamUtil.requireNonNull("objectId", objectId);
  }

  public P11CryptService p11CryptService() {
    return p11CryptService;
  }

  public P11SlotIdentifier slot() {
    return slot;
  }

  public P11ObjectIdentifier objectId() {
    return objectId;
  }

  public static P11KeyParameter getInstance(P11CryptService p11CryptService,
      P11SlotIdentifier slot, P11ObjectIdentifier objectId) throws InvalidKeyException {
    return new P11KeyParameter(p11CryptService, slot, objectId);
  }

}
