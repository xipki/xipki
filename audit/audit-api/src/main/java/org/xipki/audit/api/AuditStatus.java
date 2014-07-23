/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.audit.api;

/**
 * @author Lijun Liao
 */

public enum AuditStatus
{
    SUCCSEEFULL(0),
    FAILED(1),
    OK(2),
    ERROR(3),
    DENIED(4),
    GRANTED(5),
    UNDEFINED(6);

    private final int value;

    private AuditStatus(final int value)
    {
        this.value = value;
    }

    public int getValue()
    {
        return value;
    }

    public static final AuditStatus forName(final String name)
    {
        if(name == null)
        {
            return null;
        }

        for (AuditStatus v : values())
        {
            if (v.name().equals(name))
            {
                return v;
            }
        }
        return null;
    }

    public static final AuditStatus forValue(final int value)
    {
        for (AuditStatus v : values())
        {
            if (v.getValue() == value)
            {
                return v;
            }
        }
        return null;
    }

}
