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

public class DirPathCompleterImpl
extends PathCompleter
implements DirPathCompleter
{

    @Override
    protected boolean isDirOnly()
    {
        return true;
    }

}
