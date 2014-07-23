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

public class BadCertTemplateException extends Exception
{

    private static final long serialVersionUID = 1L;

    public BadCertTemplateException()
    {
    }

    public BadCertTemplateException(String message)
    {
        super(message);
    }

    public BadCertTemplateException(Throwable cause)
    {
        super(cause);
    }

    public BadCertTemplateException(String message, Throwable cause)
    {
        super(message, cause);
    }

}
