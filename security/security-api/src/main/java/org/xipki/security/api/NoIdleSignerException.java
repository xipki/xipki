/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api;

/**
 * @author Lijun Liao
 */

public class NoIdleSignerException extends Exception
{

    private static final long serialVersionUID = 1L;

    public NoIdleSignerException()
    {
    }

    public NoIdleSignerException(String message)
    {
        super(message);
    }

    public NoIdleSignerException(Throwable cause)
    {
        super(cause);
    }

    public NoIdleSignerException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
