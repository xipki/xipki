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

public interface P11PasswordRetriever
{
    List<char[]> getPassword(P11SlotIdentifier slotId)
    throws PasswordResolverException;

}
