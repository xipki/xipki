/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.console.karaf;

import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

import org.apache.karaf.shell.console.Completer;
import org.apache.karaf.shell.console.completer.StringsCompleter;

/**
 * @author Lijun Liao
 */

public class EnumCompleter implements Completer
{
    private final List<String> enums = new LinkedList<>();

    public void setTokens(String tokens)
    {
        StringTokenizer st = new StringTokenizer(tokens, ", ");
        while(st.hasMoreTokens())
        {
            enums.add(st.nextToken());
        }
    }

    @Override
    public int complete(String buffer, int cursor, List<String> candidates)
    {
        StringsCompleter delegate = new StringsCompleter();
        for(String entry : enums)
        {
            delegate.getStrings().add(entry);
        }
        return delegate.complete(buffer, cursor, candidates);
    }

}
