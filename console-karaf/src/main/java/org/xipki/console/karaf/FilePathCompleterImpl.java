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

public class FilePathCompleterImpl
extends PathCompleter
implements FilePathCompleter
{

    @Override
    protected boolean isDirOnly()
    {
        return false;
    }

}
