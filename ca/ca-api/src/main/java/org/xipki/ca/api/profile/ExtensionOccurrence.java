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

public class ExtensionOccurrence
{
    public static final ExtensionOccurrence CRITICAL_REQUIRED    = new ExtensionOccurrence(true, true);
    public static final ExtensionOccurrence CRITICAL_OPTIONAL    = new ExtensionOccurrence(true, false);
    public static final ExtensionOccurrence NONCRITICAL_REQUIRED = new ExtensionOccurrence(false, true);
    public static final ExtensionOccurrence NONCRITICAL_OPTIONAL = new ExtensionOccurrence(false, false);

    private final boolean critical;
    private final boolean required;

    public static ExtensionOccurrence getInstance(boolean required, boolean critical)
    {
        if(critical)
        {
            return required ? CRITICAL_REQUIRED : CRITICAL_OPTIONAL;
        }
        else
        {
            return required ? NONCRITICAL_REQUIRED : NONCRITICAL_OPTIONAL;
        }
    }

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

}
