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

package org.xipki.ca.api.profile;

/**
 * @author Lijun Liao
 */

public enum ExtensionOccurrence
{
    CRITICAL_REQUIRED(true, true),
    CRITICAL_OPTIONAL(true, false),
    NONCRITICAL_REQUIRED(false, true),
    NONCRITICAL_OPTIONAL(false, false);

    private final boolean critical;
    private final boolean required;

    private ExtensionOccurrence(boolean critical, boolean required)
    {
        this.critical = critical;
        this.required = required;
    }

    public boolean isCritical()
    {
        return critical;
    }

    public boolean isRequired()
    {
        return required;
    }

    public static ExtensionOccurrence getInstance(boolean critical, boolean required)
    {
        for(ExtensionOccurrence value : values())
        {
            if(value.critical == critical && value.required == required)
            {
                return value;
            }
        }

        throw new RuntimeException("Could not reach here");
    }

}
