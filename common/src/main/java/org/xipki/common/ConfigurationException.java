/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.common;

/**
 * @author Lijun Liao
 */

public class ConfigurationException extends Exception
{

    private static final long serialVersionUID = 1L;

    public ConfigurationException()
    {
    }

    public ConfigurationException(String message)
    {
        super(message);
    }

    public ConfigurationException(Throwable cause)
    {
        super(cause);
    }

    public ConfigurationException(String message, Throwable cause)
    {
        super(message, cause);
    }

}
