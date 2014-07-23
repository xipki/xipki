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

public class PasswordResolverException extends Exception
{

    private static final long serialVersionUID = 1L;

    public PasswordResolverException()
    {
    }

    public PasswordResolverException(String message)
    {
        super(message);
    }

    public PasswordResolverException(Throwable cause)
    {
        super(cause);
    }

    public PasswordResolverException(String message, Throwable cause)
    {
        super(message, cause);
    }

}
