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

import static org.xipki.util.Args.notNull;

import java.security.InvalidKeyException;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * {@link AsymmetricKeyParameter} for PKCS#11 private key.
 *
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

    this.p11CryptService = notNull(p11CryptService, "p11CryptService");
    this.slot = notNull(slot, "slot");
    this.objectId = notNull(objectId, "objectId");
  }

  public P11CryptService getP11CryptService() {
    return p11CryptService;
  }

  public P11SlotIdentifier getSlot() {
    return slot;
  }

  public P11ObjectIdentifier getObjectId() {
    return objectId;
  }

  public static P11KeyParameter getInstance(P11CryptService p11CryptService,
      P11SlotIdentifier slot, P11ObjectIdentifier objectId)
          throws InvalidKeyException {
    return new P11KeyParameter(p11CryptService, slot, objectId);
  }

}
