/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.certprofile;

import java.util.Set;

import org.xipki.ca.api.profile.KeyUsage;

/**
 * @author Lijun Liao
 */

class KeyUsageOption
{
    private final Condition condition;
    private final Set<KeyUsage> keyusages;

    public KeyUsageOption(Condition condition, Set<KeyUsage> keyusages)
    {
        this.condition = condition;
        this.keyusages = keyusages;
    }

    public Condition getCondition()
    {
        return condition;
    }

    public Set<KeyUsage> getKeyusages()
    {
        return keyusages;
    }

}
