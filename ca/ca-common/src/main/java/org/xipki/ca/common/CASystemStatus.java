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

public enum CASystemStatus
{
    STARTED (0),
    NOT_INITED (1),
    INITIALIZING (2),
    LOCK_FAILED (3),
    ERROR (4);

    private final int code;

    private CASystemStatus(int code)
    {
        this.code = code;
    }

    public int getCode()
    {
        return code;
    }

    @Override
    public String toString()
    {
        return code + ": " + name();
    }

}
