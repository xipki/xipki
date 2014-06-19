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

package org.xipki.ca.server.mgmt.shell;

import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.xipki.ca.server.mgmt.CAManager;

/**
 * @author Lijun Liao
 */

public abstract class CaCommand extends OsgiCommandSupport
{
    protected final static String permissionsText =
            "enroll, revoke, unrevoke, remove, key-update, gen-crl, get-crl, enroll-cross, all";

    protected CAManager caManager;

    public void setCaManager(CAManager caManager)
    {
        this.caManager = caManager;
    }

    protected Boolean isEnabled(String enabledS, String optionName)
    {
        if(enabledS == null)
        {
            return null;
        }

        if("yes".equalsIgnoreCase(enabledS))
        {
            return true;
        }
        else if("no".equalsIgnoreCase(enabledS))
        {
            return false;
        }
        else
        {
            throw new IllegalArgumentException("invalid option " + optionName + ": " + enabledS);
        }
    }

    protected boolean isEnabled(String enabledS, boolean defaultEnabled, String optionName)
    {
        if(enabledS == null)
        {
            return defaultEnabled;
        }

        if("yes".equalsIgnoreCase(enabledS))
        {
            return true;
        }
        else if("no".equalsIgnoreCase(enabledS))
        {
            return false;
        }
        else
        {
            throw new IllegalArgumentException("invalid option " + optionName + ": " + enabledS);
        }
    }

    protected static String getRealString(String s)
    {
        return CAManager.NULL.equalsIgnoreCase(s) ? null : s;
    }
}
