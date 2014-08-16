/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell.cert;

import org.xipki.ca.server.mgmt.ExtendedCAManager;
import org.xipki.ca.server.mgmt.api.CAManager;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.console.karaf.XipkiOsgiCommandSupport;

/**
 * @author Lijun Liao
 */

public abstract class CaCertCommand extends XipkiOsgiCommandSupport
{
    protected ExtendedCAManager caManager;

    public void setCaManager(ExtendedCAManager caManager)
    {
        this.caManager = caManager;
    }

    protected DuplicationMode getDuplicationMode(String mode, DuplicationMode defaultMode)
    {
        if(mode == null)
        {
            return defaultMode;
        }
        return DuplicationMode.getInstance(mode);
    }

    protected static String getRealString(String s)
    {
        return CAManager.NULL.equalsIgnoreCase(s) ? null : s;
    }
}
