/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.audit.api;

import java.util.Arrays;
import java.util.Date;

public class AuditEventData
{
    public static final int STRING_MAX_LENGTH = 255;

    private final String name;

    private final AuditEventDataType eventDataType;

    private final Object value;

    public AuditEventData(final String name, final byte[] value)
    {
        if(name == null || name.isEmpty())
        {
            throw new IllegalArgumentException("name could not be null");
        }
        if(value == null)
        {
            throw new IllegalArgumentException("value could not be null");
        }

        eventDataType = AuditEventDataType.BINARY;

        this.name = name;
        this.value = value;
    }

    public AuditEventData(final String name, final Date value)
    {
        if(name == null || name.isEmpty())
        {
            throw new IllegalArgumentException("name could not be null");
        }
        if(value == null)
        {
            throw new IllegalArgumentException("value could not be null");
        }

        eventDataType = AuditEventDataType.TIMESTAMP;

        this.name = name;
        this.value = value;
    }

    public AuditEventData(final String name, final Number value)
    {
        if(name == null || name.isEmpty())
        {
            throw new IllegalArgumentException("name could not be null");
        }
        if(value == null)
        {
            throw new IllegalArgumentException("value could not be null");
        }

        eventDataType = AuditEventDataType.NUMBER;
        this.name = name;
        this.value = value;
    }

    public AuditEventData(final String name, final String value)
    {
        if(name == null || name.isEmpty())
        {
            throw new IllegalArgumentException("name could not be null");
        }
        if(value == null)
        {
            throw new IllegalArgumentException("value could not be null");
        }

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

}
