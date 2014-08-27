/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api.p11;

import java.util.List;

import org.xipki.security.api.PasswordResolverException;

/**
 * @author Lijun Liao
 */

public class P11NullPasswordRetriever implements P11PasswordRetriever
{
    public static final P11NullPasswordRetriever INSTANCE = new P11NullPasswordRetriever();

    @Override
    public List<char[]> getPassword(P11SlotIdentifier slotId)
    throws PasswordResolverException
    {
        return null;
    }
}
