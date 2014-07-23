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

public enum AuditLevel
{
    EMERGENCY(0, "EMERGENCY"),
    ALERT(1,     "ALERT    "),
    CRITICAL(2,  "CRITICAL "),
    ERROR(3,     "ERROR    "),
    WARN(4,      "WARN     "),
    NOTICE(5,    "NOTICE   "),
    INFO(6,      "INFO     "),
    DEBUG(7,     "DEBUG    ");

    private final int value;
    private final String alignedText;

    private AuditLevel(int value, String alignedText)
    {
        this.value = value;
        this.alignedText = alignedText;
    }

    public int getValue()
    {
        return value;
    }

    public static final AuditLevel forName(String name)
    {
        if(name == null)
        {
            return null;
        }

        for (AuditLevel value : values())
        {
            if (value.name().equals(name))
            {
                return value;
            }
        }
        return null;
    }

    public static final AuditLevel forValue(final int value)
    {
        for (AuditLevel v : values())
        {
            if (v.getValue() == value)
            {
                return v;
            }
        }
        return null;
    }

    public String getAlignedText()
    {
        return alignedText;
    }

}
