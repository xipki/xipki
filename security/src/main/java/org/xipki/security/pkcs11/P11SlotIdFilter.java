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

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class P11SlotIdFilter {

  private final Integer index;

  private final Long id;

  P11SlotIdFilter(Integer index, Long id) {
    if (index == null && id == null) {
      throw new IllegalArgumentException("at least one of index and id must not be null");
    }
    this.index = index;
    this.id = id;
  }

  boolean match(P11SlotIdentifier slotId) {
    if (index != null) {
      if (index.intValue() != slotId.getIndex()) {
        return false;
      }
    }

    if (id != null) {
      if (id.longValue() != slotId.getId()) {
        return false;
      }
    }

    return true;
  }

}
