/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell.completer;

import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.console.karaf.EnumCompleter;

/**
 * @author Lijun Liao
 */

public class DuplicationModeCompleter extends EnumCompleter
{
    public DuplicationModeCompleter()
    {
        StringBuilder enums = new StringBuilder();
        for(DuplicationMode mode : DuplicationMode.values())
        {
            enums.append(mode.getDescription()).append(",");
        }
        enums.deleteCharAt(enums.length() - 1);
        setTokens(enums.toString());
    }

}
