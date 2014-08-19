/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.common;

/**
 * @author Lijun Liao
 */

public class CertAlreadyIssuedException extends Exception
{

    private static final long serialVersionUID = 1L;

    public CertAlreadyIssuedException()
    {
    }

    public CertAlreadyIssuedException(String message)
    {
        super(message);
    }

    public CertAlreadyIssuedException(Throwable cause)
    {
        super(cause);
    }

    public CertAlreadyIssuedException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
