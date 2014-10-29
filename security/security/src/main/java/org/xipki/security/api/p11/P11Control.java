/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api.p11;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author Lijun Liao
 */

public class P11Control
{
    private final String defaultModuleName;
    private final Map<String, P11ModuleConf> moduleConfs;
    private final Set<String> moduleNames;

    public P11Control(String defaultModuleName, Set<P11ModuleConf> moduleConfs)
    {
        if(defaultModuleName == null || defaultModuleName.isEmpty())
        {
            throw new IllegalArgumentException("defaultModuleName could not be null or empty");
        }

        this.defaultModuleName = defaultModuleName;
        if(moduleConfs == null || moduleConfs.isEmpty())
        {
            this.moduleConfs = Collections.emptyMap();
            this.moduleNames = Collections.emptySet();
        }
        else
        {
            this.moduleConfs = new HashMap<>(moduleConfs.size());
            Set<String> _moduleNames = new HashSet<>();
            for(P11ModuleConf conf : moduleConfs)
            {
                this.moduleConfs.put(conf.getName(), conf);
                _moduleNames.add(conf.getName());
            }
            this.moduleNames = Collections.unmodifiableSet(_moduleNames);
        }
    }

    public String getDefaultModuleName()
    {
        return defaultModuleName;
    }

    public P11ModuleConf getModuleConf(String moduleName)
    {
        return moduleConfs == null ? null : moduleConfs.get(moduleName);
    }

    public Set<String> getModuleNames()
    {
        return moduleNames;
    }

}
