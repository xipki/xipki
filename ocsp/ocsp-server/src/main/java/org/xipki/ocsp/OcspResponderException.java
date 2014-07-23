/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp;

/**
 * @author Lijun Liao
 */

public class OcspResponderException extends Exception
{

    private static final long serialVersionUID = 1L;

    public OcspResponderException()
    {
    }

    public OcspResponderException(String message)
    {
        super(message);
    }

    public OcspResponderException(Throwable cause)
    {
        super(cause);
    }

    public OcspResponderException(String message, Throwable cause)
    {
        super(message, cause);
    }

}
