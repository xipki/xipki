/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell;

import org.xipki.ca.client.api.RAWorker;
import org.xipki.console.karaf.XipkiOsgiCommandSupport;

/**
 * @author Lijun Liao
 */

public abstract class ClientCommand extends XipkiOsgiCommandSupport
{
    protected RAWorker raWorker;

    public final void setRaWorker(RAWorker raWorker)
    {
        this.raWorker = raWorker;
    }

}
