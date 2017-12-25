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

package org.xipki.security;

import java.security.cert.X509Certificate;

import org.xipki.common.ObjectCreationException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface SignerFactory {

    /**
     * Indicates whether a signer of the given {@code type} can be created or not.
     *
     * @param type
     *          Type of the signer. Must no be {@code null}.
     * @return true if signer of the given type can be created, false otherwise.
     */
    boolean canCreateSigner(String type);

    /**
     * Creates a new signer.
     * @param type
     *          Type of the signer. Must not be {@code null}.
     * @param conf
     *          Configuration of the signer. Must not be {@code null}.
     * @param certificateChain
     *          Certificate chain of the signer. Could be {@code null}.
     *
     * @return new signer.
     * @throws ObjectCreationException
     *         if signer could not be created.
     */
    ConcurrentContentSigner newSigner(String type, SignerConf conf,
            X509Certificate[] certificateChain) throws ObjectCreationException;

}
