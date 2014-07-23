/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell.completer;

import java.util.Set;

import org.xipki.ca.client.api.RAWorker;
import org.xipki.console.karaf.DynamicEnumCompleter;

/**
 * @author Lijun Liao
 */

public class CaNameCompleter extends DynamicEnumCompleter
{

    protected RAWorker            raWorker;

    public final void setRaWorker(RAWorker raWorker)
    {
        this.raWorker = raWorker;
    }

    @Override
    protected Set<String> getEnums()
    {
        return raWorker.getCaNames();
    }

}
