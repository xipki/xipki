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

public class AuditEventData
{
    private final String name;
    private final String value;

    public AuditEventData(
            final String name,
            final String value)
    {
        assertNotEmpty("name", name);
        assertNotNull("value", value);
        this.name = name;
        this.value = value;
    }

    public String getName()
    {
        return name;
    }

    public String getValue()
    {
        return value;
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append(": ").append(value);
        return sb.toString();
    }

    private static void assertNotNull(
            final String parameterName,
            final Object parameter)
    {
        if(parameter == null)
        {
            throw new IllegalArgumentException(parameterName + " could not be null");
        }
    }

    private static void assertNotEmpty(
            final String parameterName,
            final String parameter)
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
