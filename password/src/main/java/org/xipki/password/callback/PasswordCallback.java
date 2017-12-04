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

package org.xipki.password.callback;

import org.xipki.password.PasswordResolverException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface PasswordCallback {

    /**
     * Initializes me.
     *
     * @param conf
     *          Configuration. Could be {@code null}.
     * @throws PasswordResolverException
     *         if error occurs
     */
    void init(String conf) throws PasswordResolverException;

    /**
     * Resolves the password
     * @param prompt
     *          Prompt shown to use while asking password. Could be {@code null}.
     * @param testToken
     *          Token used to test whether the retrieved password is correct. Could be {@code null}.
     * @return the resolved password
     * @throws PasswordResolverException
     *         if error occurs
     */
    char[] getPassword(String prompt, String testToken) throws PasswordResolverException;

}
