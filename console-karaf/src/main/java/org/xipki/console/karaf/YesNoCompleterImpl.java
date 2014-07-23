/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.console.karaf;

/**
 * @author Lijun Liao
 */

public class YesNoCompleterImpl extends EnumCompleter
implements YesNoCompleter
{
    public YesNoCompleterImpl()
    {
        setTokens("yes, no");
    }
}
