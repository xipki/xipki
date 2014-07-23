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

public class CryptException extends Exception
{

    private static final long serialVersionUID = 1L;

    public CryptException()
    {
        super();
    }

    public CryptException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public CryptException(String message)
    {
        super(message);
    }

    public CryptException(Throwable cause)
    {
        super(cause);
    }
}
