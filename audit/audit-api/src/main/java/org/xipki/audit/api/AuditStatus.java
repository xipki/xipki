/*
 * Copyright (c) 2014 Lijun Liao
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
