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

package org.xipki.ocsp.api;

import org.xipki.common.ObjectCreationException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface OcspStoreFactory {

    /**
     *
     * @param type
     *          Type of the OCSP store. Must not be {@code null}.
     * @return whether OCSP store of this type can be created.
     */
    boolean canCreateOcspStore(String type);

    /**
     *
     * @param type
     *          Type of the OCSP store. Must not be {@code null}.
     * @return a new OCSP store
     */
    OcspStore newOcspStore(String type) throws ObjectCreationException;

}
