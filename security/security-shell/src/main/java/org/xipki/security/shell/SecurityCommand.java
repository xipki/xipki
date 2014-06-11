/*
 * Copyright (c) 2014 xipki.org
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

package org.xipki.security.shell;

import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.IoCertUtil;

public abstract class SecurityCommand extends OsgiCommandSupport
{

    protected SecurityFactory securityFactory;

    public SecurityFactory getSecurityFactory()
    {
        return securityFactory;
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    protected char[] readPasswordIfNotSet(String password, Boolean readFromConsole)
    {
        if(password != null)
        {
            return password.toCharArray();
        }

        if(readFromConsole != null && readFromConsole.booleanValue())
        {
            return readPassword();
        }

        return null;
    }

    protected char[] readPasswordIfNotSet(String password)
    {
        if(password != null)
        {
            return password.toCharArray();
        }

          return readPassword();
    }

    protected char[] readPassword()
    {
        return IoCertUtil.readPassword("Enter the password");
    }

}
