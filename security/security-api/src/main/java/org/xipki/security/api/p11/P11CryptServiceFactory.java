/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api.p11;

import java.util.Set;

import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public interface P11CryptServiceFactory
{
    P11CryptService createP11CryptService(String pkcs11Module, char[] password)
    throws SignerException;

    P11CryptService createP11CryptService(String pkcs11Module, char[] password,
            Set<Integer> includeSlotIndexes, Set<Integer> excludeSlotIndexes)
    throws SignerException;
}
