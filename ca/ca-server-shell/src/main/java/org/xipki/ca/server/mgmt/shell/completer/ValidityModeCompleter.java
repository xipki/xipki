/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell.completer;

import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.console.karaf.EnumCompleter;

/**
 * @author Lijun Liao
 */

public class ValidityModeCompleter extends EnumCompleter
{
    public ValidityModeCompleter()
    {
        StringBuilder enums = new StringBuilder();
        for(ValidityMode mode : ValidityMode.values())
        {
            enums.append(mode.name()).append(",");
        }
        enums.deleteCharAt(enums.length() - 1);
        setTokens(enums.toString());
    }

}
