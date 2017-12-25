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

package org.xipki.ca.server.impl.cmp;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface CmpResponderManager {

    /**
     * Returns the CA name for the alias {@code caAlias}.
     * @param caAlias
     *          CA alias. Must not be {@code null}.
     * @return CA name for the given alias.
     */
    String getCaNameForAlias(String caAlias);

    /**
     * Returns the CMP responder for the CA {@code caName}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return the CMP responder for the given CA name.
     */
    X509CaCmpResponder getX509CaResponder(String caName);

}
