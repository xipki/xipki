/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.cmp;

/**
 * @author Lijun Liao
 */

public class BadRequestException extends Exception
{

    private static final long serialVersionUID = 1L;

    public BadRequestException()
    {
    }

    public BadRequestException(String message)
    {
        super(message);
    }

    public BadRequestException(Throwable cause)
    {
        super(cause);
    }

    public BadRequestException(String message, Throwable cause)
    {
        super(message, cause);
    }

}
