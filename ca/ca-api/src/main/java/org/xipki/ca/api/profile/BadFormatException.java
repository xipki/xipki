/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.api.profile;

/**
 * @author Lijun Liao
 */

public class BadFormatException extends Exception
{

    private static final long serialVersionUID = 1L;

    public BadFormatException()
    {
    }

    public BadFormatException(String message)
    {
        super(message);
    }

    public BadFormatException(Throwable cause)
    {
        super(cause);
    }

    public BadFormatException(String message, Throwable cause)
    {
        super(message, cause);
    }

}
