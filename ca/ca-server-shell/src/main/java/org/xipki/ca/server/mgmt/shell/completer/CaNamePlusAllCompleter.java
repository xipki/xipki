/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell.completer;

import java.util.HashSet;
import java.util.Set;

/**
 * @author Lijun Liao
 */

public class CaNamePlusAllCompleter extends MgmtNameCompleter
{

    @Override
    protected Set<String> getEnums()
    {
        Set<String> ret = new HashSet<>(caManager.getCANames());
        ret.add("all");
        return ret;
    }

}
