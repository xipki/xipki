/*
 * Copyright (c) 2015 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.password;

import org.xipki.password.api.PasswordResolverException;

/**
 * SHOULD NOT BE USED IN PRODUCTION ENVIRONMENT. ONLY FOR TEST PURPOSE
 *
 * @author Lijun Liao
 */

public class DummyPBEPasswordResolver extends PBEPasswordResolver
{

    private char[] masterPassword;

    @Override
    protected char[] getMasterPassword()
    throws PasswordResolverException
    {
        if(masterPassword != null)
        {
            return masterPassword;
        }

        return super.getMasterPassword();
    }

    public void setMasterPassword(
            final char[] masterPassword)
    {
        this.masterPassword = masterPassword;
    }

}
