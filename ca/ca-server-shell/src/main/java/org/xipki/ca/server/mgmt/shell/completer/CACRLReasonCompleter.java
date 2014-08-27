/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell.completer;

import org.xipki.ca.server.mgmt.shell.CaRevokeCommand;
import org.xipki.console.karaf.EnumCompleter;
import org.xipki.security.common.CRLReason;

/**
 * @author Lijun Liao
 */

public class CACRLReasonCompleter extends EnumCompleter
{
    public CACRLReasonCompleter()
    {
        StringBuilder enums = new StringBuilder();

        for(CRLReason reason : CaRevokeCommand.permitted_reasons)
        {
            enums.append(reason.getDescription()).append(",");
        }
        enums.deleteCharAt(enums.length() - 1);
        setTokens(enums.toString());
    }
}
