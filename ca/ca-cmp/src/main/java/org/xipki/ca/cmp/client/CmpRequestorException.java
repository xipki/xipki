/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.cmp.client;

/**
 * @author Lijun Liao
 */

public class CmpRequestorException extends Exception
{
    private static final long serialVersionUID = 1L;

    public CmpRequestorException()
    {
        super();
    }

    public CmpRequestorException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public CmpRequestorException(String message)
    {
        super(message);
    }

    public CmpRequestorException(Throwable cause)
    {
        super(cause);
    }

}
