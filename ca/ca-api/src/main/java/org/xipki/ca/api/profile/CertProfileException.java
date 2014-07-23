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

public class CertProfileException extends Exception
{

    private static final long serialVersionUID = 1L;

    public CertProfileException()
    {
    }

    public CertProfileException(String message)
    {
        super(message);
    }

    public CertProfileException(Throwable cause)
    {
        super(cause);
    }

    public CertProfileException(String message, Throwable cause)
    {
        super(message, cause);
    }

}
