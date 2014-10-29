/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.api;

/**
 * @author Lijun Liao
 */

public class CertStatusStoreException extends Exception
{

    private static final long serialVersionUID = 1L;

    public CertStatusStoreException()
    {
    }

    public CertStatusStoreException(String message)
    {
        super(message);
    }

    public CertStatusStoreException(Throwable cause)
    {
        super(cause);
    }

    public CertStatusStoreException(String message, Throwable cause)
    {
        super(message, cause);
    }

}
