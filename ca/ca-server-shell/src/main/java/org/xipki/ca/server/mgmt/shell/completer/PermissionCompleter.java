/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell.completer;

import org.xipki.ca.server.mgmt.shell.CaCommand;
import org.xipki.console.karaf.EnumCompleter;

/**
 * @author Lijun Liao
 */

public class PermissionCompleter extends EnumCompleter
{
    public PermissionCompleter()
    {
        super.setTokens(CaCommand.permissionsText);
    }
}
