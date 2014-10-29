/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.certprofile;

import org.xipki.ca.api.profile.ExtensionTuple;

/**
 * @author Lijun Liao
 */

class ExtensionTupleOption
{
    private final Condition condition;
    private final ExtensionTuple extensionTuple;

    public ExtensionTupleOption(Condition condition, ExtensionTuple extensionTuple)
    {
        this.condition = condition;
        this.extensionTuple = extensionTuple;
    }

    public Condition getCondition()
    {
        return condition;
    }

    public ExtensionTuple getExtensionTuple()
    {
        return extensionTuple;
    }

}
