/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.util.List;

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

    protected static String toString(List<? extends Object> list)
    {
        StringBuilder sb = new StringBuilder();
        if(list == null)
        {
            sb.append("null");
        }

        sb.append("{");
        int n = list.size();
        for(int i = 0; i < n; i++)
        {
            Object o = list.get(i);
            sb.append(o);
            if(i == n - 1 && n != 0)
            {
                sb.append(", ");
            }
        }
        sb.append("}");
        return sb.toString();
    }
}
