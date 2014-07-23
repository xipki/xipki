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

public class SignerException extends Exception
{

    private static final long serialVersionUID = 1L;

    public SignerException()
    {
        super();
    }

    public SignerException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public SignerException(String message)
    {
        super(message);
    }

    public SignerException(Throwable cause)
    {
        super(cause);
    }
}
