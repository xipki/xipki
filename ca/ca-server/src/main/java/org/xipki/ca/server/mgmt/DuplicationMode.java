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

package org.xipki.ca.server.mgmt;

/**
 * @author Lijun Liao
 */

public enum DuplicationMode
{
    FORBIDDEN (1, "forbidden"),
    FORBIDDEN_WITHIN_PROFILE (2, "forbiddenWithinProfile"),
    PERMITTED (3, "permitted");

    private final int mode;
    private final String description;

    private DuplicationMode(int mode, String description)
    {
        this.mode = mode;
        this.description = description;
    }

    public int getMode()
    {
        return mode;
    }

    public String getDescription()
    {
        return description;
    }

    public static DuplicationMode getInstance(String text)
    {
        for(DuplicationMode value : values())
        {
            if(value.description.equalsIgnoreCase(text) ||
                    value.name().equalsIgnoreCase(text) ||
                    Integer.toString(value.mode).equalsIgnoreCase(text))
            {
                return value;
            }
        }

        return null;
    }

    public static DuplicationMode getInstance(int mode)
    {
        for(DuplicationMode value : values())
        {
            if(mode == value.mode)
            {
                return value;
            }
        }

        return null;
    }
}
