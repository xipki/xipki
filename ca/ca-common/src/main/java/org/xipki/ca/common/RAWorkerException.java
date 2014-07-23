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

public class RAWorkerException extends Exception
{

    private static final long serialVersionUID = 1L;

    public RAWorkerException()
    {
    }

    public RAWorkerException(String message)
    {
        super(message);
    }

    public RAWorkerException(Throwable cause)
    {
        super(cause);
    }

    public RAWorkerException(String message, Throwable cause)
    {
        super(message, cause);
    }

}
