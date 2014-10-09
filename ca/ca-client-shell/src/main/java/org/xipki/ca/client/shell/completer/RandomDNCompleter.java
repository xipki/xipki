/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell.completer;

import org.xipki.ca.client.shell.loadtest.LoadTestEntry.RandomDN;
import org.xipki.console.karaf.EnumCompleter;

/**
 * @author Lijun Liao
 */

public class RandomDNCompleter extends EnumCompleter
{

    public RandomDNCompleter()
    {
        StringBuilder enums = new StringBuilder();

        for(RandomDN dn : RandomDN.values())
        {
            enums.append(dn.name()).append(",");
        }
        enums.deleteCharAt(enums.length() - 1);
        setTokens(enums.toString());
    }

}
