/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.console.karaf;

import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.console.Completer;
import org.apache.karaf.shell.console.completer.StringsCompleter;

/**
 * @author Lijun Liao
 */

public abstract class DynamicEnumCompleter implements Completer
{
    protected abstract Set<String> getEnums();

    @Override
    public int complete(String buffer, int cursor, List<String> candidates)
    {
        StringsCompleter delegate = new StringsCompleter();

        for(String s : getEnums())
        {
            delegate.getStrings().add(s);
        }

        return delegate.complete(buffer, cursor, candidates);
    }

}
