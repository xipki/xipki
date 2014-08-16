/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell.completer;

import org.xipki.ca.server.mgmt.api.CAManager;
import org.xipki.console.karaf.DynamicEnumCompleter;

/**
 * @author Lijun Liao
 */

public abstract class MgmtNameCompleter extends DynamicEnumCompleter
{
    protected CAManager caManager;

    public void setCaManager(CAManager caManager)
    {
        this.caManager = caManager;
    }

}
