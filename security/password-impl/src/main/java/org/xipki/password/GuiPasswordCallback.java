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

import org.xipki.password.api.PasswordCallback;
import org.xipki.password.api.PasswordResolverException;
import org.xipki.password.api.SecurePasswordInputPanel;
import org.xipki.password.api.util.StringUtil;

/**
 * @author Lijun Liao
 */

public class GuiPasswordCallback implements PasswordCallback
{
    @Override
    public char[] getPassword(
            String prompt)
    throws PasswordResolverException
    {
        if(StringUtil.isBlank(prompt))
        {
            prompt = "Password required";
        }
        char[] password = SecurePasswordInputPanel.readPassword(prompt);
        if(password == null)
        {
            throw new PasswordResolverException("user has cancelled");
        }
        return password;
    }

    @Override
    public void init(
            final String conf)
    throws PasswordResolverException
    {
    }
}
