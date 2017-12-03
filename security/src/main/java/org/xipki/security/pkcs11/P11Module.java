/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

import java.util.List;

import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.P11UnknownEntityException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface P11Module {

    String getName();

    P11ModuleConf getConf();

    boolean isReadOnly();

    List<P11SlotIdentifier> slotIdentifiers();

    /**
     *
     * @param slotId
     *          Slot identifier. Must not be {@code null}.
     * @throws P11TokenException
     */
    P11Slot getSlot(P11SlotIdentifier slotId) throws P11TokenException;

    P11SlotIdentifier getSlotIdForIndex(int index) throws P11UnknownEntityException;

    P11SlotIdentifier getSlotIdForId(long id) throws P11UnknownEntityException;

    void close();

}
