/*
 * Copyright (c) 2015 Lijun Liao
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

public enum AuditLevel
{
    ERROR    (3, "ERROR    "),
    WARN     (4, "WARN     "),
    INFO     (6, "INFO     "),
    DEBUG    (7, "DEBUG    ");

    private final int value;
    private final String alignedText;

    private AuditLevel(
            final int value,
            final String alignedText)
    {
        this.value = value;
        this.alignedText = alignedText;
    }

    public int getValue()
    {
        return value;
    }

    public static final AuditLevel forName(
            final String name)
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

    public static final AuditLevel forValue(
            final int value)
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
