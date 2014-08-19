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

public class CertPublisherException extends Exception
{

    private static final long serialVersionUID = 1L;

    public CertPublisherException()
    {
    }

    public CertPublisherException(String message)
    {
        super(message);
    }

    public CertPublisherException(Throwable cause)
    {
        super(cause);
    }

    public CertPublisherException(String message, Throwable cause)
    {
        super(message, cause);
    }

}
