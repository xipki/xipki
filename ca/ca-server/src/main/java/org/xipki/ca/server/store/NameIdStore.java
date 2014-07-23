/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.store;

import java.util.HashMap;
import java.util.Map;

import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class NameIdStore
{
    private final String table;
    private final Map<String, Integer> entries;
    private int nextFreeId;

    NameIdStore(String table, Map<String, Integer> entries)
    {
        this.table = table;
        this.entries = new HashMap<>();

        for(String name : entries.keySet())
        {
            addEntry(name, entries.get(name));
        }

        if(nextFreeId < 1)
        {
            nextFreeId = 1;
        }
    }

    synchronized void addEntry(String name, Integer id)
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotNull("id", id);

        if(entries.containsKey(name))
        {
            throw new IllegalArgumentException("entry with the same name " + name + " already available");
        }

        if(entries.containsValue(id))
        {
            throw new IllegalArgumentException("entry with the same id " + id + " already available");
        }

        if(nextFreeId <= id)
        {
            nextFreeId = id + 1;
        }

        entries.put(name, id);
    }

    synchronized String getName(Integer id)
    {
        for(String name : entries.keySet())
        {
            if(id == entries.get(name))
            {
                return name;
            }
        }

        return null;
    }

    synchronized Integer getId(String name)
    {
        return entries.get(name);
    }

    synchronized int getNextFreeId()
    {
        return nextFreeId++;
    }

    public String getTable()
    {
        return table;
    }

}
