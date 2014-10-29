/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api.p11;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Lijun Liao
 */

public class P11ModuleConf
{
    private final String name;
    private final String nativeLibrary;
    private final Set<P11SlotIdentifier> excludeSlots;
    private final Set<P11SlotIdentifier> includeSlots;
    private final P11PasswordRetriever passwordRetriever;

    public P11ModuleConf(String name, String nativeLibrary, P11PasswordRetriever passwordRetriever)
    {
        this(name, nativeLibrary, passwordRetriever, null, null);
    }

    public P11ModuleConf(
            String name, String nativeLibrary, P11PasswordRetriever passwordRetriever,
            Set<P11SlotIdentifier> includeSlots, Set<P11SlotIdentifier> excludeSlots)
    {
        if(name == null || name.isEmpty())
        {
            throw new IllegalArgumentException("name could not be null or empty");
        }

        if(nativeLibrary == null || nativeLibrary.isEmpty())
        {
            throw new IllegalArgumentException("nativeLibrary could not be null or empty");
        }

        this.name = name.toLowerCase();
        this.nativeLibrary = nativeLibrary;
        this.passwordRetriever = passwordRetriever == null ? P11NullPasswordRetriever.INSTANCE : passwordRetriever;

        Set<P11SlotIdentifier> set = new HashSet<>();
        if(includeSlots != null)
        {
            set.addAll(includeSlots);
        }
        this.includeSlots = Collections.unmodifiableSet(set);

        set = new HashSet<>();
        if(excludeSlots != null)
        {
            set.addAll(excludeSlots);
        }
        this.excludeSlots = Collections.unmodifiableSet(set);
    }

    public String getName()
    {
        return name;
    }

    public String getNativeLibrary()
    {
        return nativeLibrary;
    }

    public Set<P11SlotIdentifier> getExcludeSlots()
    {
        return excludeSlots;
    }

    public Set<P11SlotIdentifier> getIncludeSlots()
    {
        return includeSlots;
    }

    public P11PasswordRetriever getPasswordRetriever()
    {
        return passwordRetriever;
    }

    public boolean isSlotIncluded(P11SlotIdentifier slot)
    {
        boolean included;
        if(includeSlots == null || includeSlots.isEmpty())
        {
            included = true;
        }
        else
        {
            included = false;
            for(P11SlotIdentifier _slot : includeSlots)
            {
                if(_slot.equals(slot))
                {
                    included = true;
                    break;
                }
            }
        }

        if(included == false)
        {
            return false;
        }

        if(excludeSlots == null || excludeSlots.isEmpty())
        {
            return included;
        }

        for(P11SlotIdentifier _slot : excludeSlots)
        {
            if(_slot.equals(slot))
            {
                return false;
            }
        }

        return true;
    }

}
