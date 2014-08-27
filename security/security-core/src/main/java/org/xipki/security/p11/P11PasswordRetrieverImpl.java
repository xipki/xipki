/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.p11.P11PasswordRetriever;
import org.xipki.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 */

public class P11PasswordRetrieverImpl implements P11PasswordRetriever
{
    private static final class SingleRetriever
    {
        private final Set<P11SlotIdentifier> slots;
        private final List<String> singlePasswords;

        private SingleRetriever(Set<P11SlotIdentifier> slots, List<String> singlePasswords)
        {
            this.slots = slots;
            if(singlePasswords == null || singlePasswords.isEmpty())
            {
                this.singlePasswords = null;
            }
            else
            {
                this.singlePasswords = singlePasswords;
            }
        }

        public boolean match(P11SlotIdentifier pSlot)
        {
            if(slots == null)
            {
                return true;
            }
            for(P11SlotIdentifier slot : slots)
            {
                if(slot.equals(pSlot))
                {
                    return true;
                }
            }

            return false;
        }

        public List<char[]> getPasswords(PasswordResolver passwordResolver)
        throws PasswordResolverException
        {
            if(singlePasswords == null)
            {
                return null;
            }

            List<char[]> ret = new ArrayList<char[]>(singlePasswords.size());
            for(String singlePassword : singlePasswords)
            {
                   ret.add(passwordResolver.resolvePassword(singlePassword));
            }

            return ret;
        }

    }

    private final List<SingleRetriever> singleRetrievers;
    private PasswordResolver passwordResolver;

    public P11PasswordRetrieverImpl()
    {
        singleRetrievers = new LinkedList<>();
    }

    public void addPasswordEntry(Set<P11SlotIdentifier> slots, List<String> singlePasswords)
    {
        singleRetrievers.add(new SingleRetriever(slots, singlePasswords));
    }

    @Override
    public List<char[]> getPassword(P11SlotIdentifier slotId)
    throws PasswordResolverException
    {
        if(singleRetrievers.isEmpty())
        {
            return null;
        }

        if(passwordResolver == null)
        {
            throw new PasswordResolverException("passwordResolver is not set");
        }

        for(SingleRetriever sr : singleRetrievers)
        {
            if(sr.match(slotId))
            {
                return sr.getPasswords(passwordResolver);
            }
        }

        return null;
    }

    public PasswordResolver getPasswordResolver()
    {
        return passwordResolver;
    }

    public void setPasswordResolver(PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }

}
