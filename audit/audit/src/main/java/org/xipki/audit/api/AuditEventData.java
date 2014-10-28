/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
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
