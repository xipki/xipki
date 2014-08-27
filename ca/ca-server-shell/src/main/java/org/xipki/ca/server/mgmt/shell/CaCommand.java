/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.xipki.ca.server.mgmt.api.CAManager;
import org.xipki.console.karaf.XipkiOsgiCommandSupport;

/**
 * @author Lijun Liao
 */

public abstract class CaCommand extends XipkiOsgiCommandSupport
{
    public final static String permissionsText =
            "enroll, revoke, unrevoke, remove, key-update, gen-crl, get-crl, enroll-cross, all";

    protected CAManager caManager;

    public void setCaManager(CAManager caManager)
    {
        this.caManager = caManager;
    }

    protected static String getRealString(String s)
    {
        return CAManager.NULL.equalsIgnoreCase(s) ? null : s;
    }
}
