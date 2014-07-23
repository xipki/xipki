/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.client.api;

/**
 * @author Lijun Liao
 */

public class OCSPRequestorException extends Exception
{

    private static final long serialVersionUID = 1L;

    public OCSPRequestorException()
    {
    }

    public OCSPRequestorException(String message)
    {
        super(message);
    }

    public OCSPRequestorException(Throwable cause)
    {
        super(cause);
    }

    public OCSPRequestorException(String message, Throwable cause)
    {
        super(message, cause);
    }

}
