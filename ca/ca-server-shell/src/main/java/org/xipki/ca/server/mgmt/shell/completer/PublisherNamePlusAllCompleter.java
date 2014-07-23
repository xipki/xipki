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

public class PublisherNamePlusAllCompleter extends MgmtNameCompleter
{

    @Override
    protected Set<String> getEnums()
    {
        Set<String> ret = new HashSet<>(caManager.getPublisherNames());
        ret.add("all");
        return ret;
    }
}
