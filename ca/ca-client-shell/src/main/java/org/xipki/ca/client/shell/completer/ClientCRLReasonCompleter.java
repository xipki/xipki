/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell.completer;

import org.xipki.common.CRLReason;
import org.xipki.console.karaf.EnumCompleter;

/**
 * @author Lijun Liao
 */

public class ClientCRLReasonCompleter extends EnumCompleter
{
    public ClientCRLReasonCompleter()
    {
        StringBuilder enums = new StringBuilder();

        for(CRLReason reason : CRLReason.PERMITTED_CLIENT_CRLREASONS)
        {
            enums.append(reason.getDescription()).append(",");
        }
        enums.deleteCharAt(enums.length() - 1);
        setTokens(enums.toString());
    }
}
