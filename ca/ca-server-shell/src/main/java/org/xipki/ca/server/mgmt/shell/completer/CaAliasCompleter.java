/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell.completer;

import java.util.List;

import org.apache.karaf.shell.console.Completer;
import org.apache.karaf.shell.console.completer.StringsCompleter;
import org.xipki.ca.server.mgmt.CAManager;

/**
 * @author Lijun Liao
 */

public class CaAliasCompleter implements Completer
{
    private CAManager caManager;

    public void setCaManager(CAManager caManager)
    {
        this.caManager = caManager;
    }

    @Override
    public int complete(String buffer, int cursor, List<String> candidates)
    {
        StringsCompleter delegate = new StringsCompleter();

        for(String s : caManager.getCaAliasNames())
        {
            delegate.getStrings().add(s);
        }

        return delegate.complete(buffer, cursor, candidates);
    }

}
