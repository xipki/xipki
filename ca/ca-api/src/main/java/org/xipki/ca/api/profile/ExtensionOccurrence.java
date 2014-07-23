/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
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
