/*
 * Copyright (c) 2014 xipki.org
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

public enum AuditLevel
{
    EMERGENCY(0),
    ALERT(1),
    CRITICAL(2),
    ERROR(3),
    WARN(4),
    NOTICE(5),
    INFO(6),
    DEBUG(7);

    private final int value;

    private AuditLevel(int value)
    {
        this.value = value;
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

}
