/*
 * Copyright (c) 2014 Lijun Liao
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

import org.xipki.console.karaf.XipkiOsgiCommandSupport;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

public abstract class SecurityCommand extends XipkiOsgiCommandSupport
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

    protected char[] readPasswordIfRequired(String password, Boolean readFromConsole)
    {
        if(password != null)
        {
            return password.toCharArray();
        }
        else
        {
            return isTrue(readFromConsole) ? readPassword() : null;
        }
    }

}
