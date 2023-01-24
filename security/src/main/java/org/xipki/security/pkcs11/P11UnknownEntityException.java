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

/**
 * Exception indicates unknown PKCS#11 entity.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11UnknownEntityException extends P11TokenException {

  public P11UnknownEntityException(P11IdentityId identityId) {
    super("unknown identity '" + identityId + "'");
  }

  public P11UnknownEntityException(P11SlotId slotId) {
    super("unknown slot '" + slotId + "'");
  }

  public P11UnknownEntityException(P11SlotId slotId, P11ObjectId objectId) {
    super("unknown entity 'slot " + slotId + ", object " + objectId + "'");
  }

  public P11UnknownEntityException(String message) {
    super(message);
  }

}
