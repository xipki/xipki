/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.audit.api;

import java.util.Arrays;
import java.util.Date;

/**
 * @author Lijun Liao
 */

public class AuditEventData
{

    public static final int STRING_MAX_LENGTH = 255;

    private final String name;

    private final AuditEventDataType eventDataType;

    private final Object value;

    public AuditEventData(final String name, final byte[] value)
    {
        assertNotEmpty("name", name);
        assertNotNull("value", value);

        eventDataType = AuditEventDataType.BINARY;

        this.name = name;
        this.value = value;
    }

    public AuditEventData(final String name, final Date value)
    {
        assertNotEmpty("name", name);
        assertNotNull("value", value);

        eventDataType = AuditEventDataType.TIMESTAMP;

        this.name = name;
        this.value = value;
    }

    public AuditEventData(final String name, final Number value)
    {
        assertNotEmpty("name", name);
        assertNotNull("value", value);

        eventDataType = AuditEventDataType.NUMBER;
        this.name = name;
        this.value = value;
    }

    public AuditEventData(final String name, final String value)
    {
        assertNotEmpty("name", name);
        assertNotNull("value", value);

        eventDataType = AuditEventDataType.TEXT;
        this.name = name;
        this.value = value;
    }

    public AuditEventDataType getEventDataType()
    {
        return eventDataType;
    }

    public String getName()
    {
        return name;
    }

    public Number getNumberValue()
    {
        return (Number) value;
    }

    public String getTextValue()
    {
        return (String) value;
    }

    public Date getTimestampValue()
    {
        return (Date) value;
    }

    public byte[] getBinaryValue()
    {
        byte[] binaryValue = (byte[]) value;
        return Arrays.copyOf(binaryValue, binaryValue.length);
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append("=").append(value);
        return sb.toString();
    }

    private static void assertNotNull(String parameterName, Object parameter)
    {
        if(parameter == null)
        {
            throw new IllegalArgumentException(parameterName + " could not be null");
        }
    }

    private static void assertNotEmpty(String parameterName, String parameter)
    {
        if(parameter == null)
        {
            throw new IllegalArgumentException(parameterName + " could not be null");
        }

        if(parameter.isEmpty())
        {
            throw new IllegalArgumentException(parameterName + " could not be empty");
        }
    }

}
