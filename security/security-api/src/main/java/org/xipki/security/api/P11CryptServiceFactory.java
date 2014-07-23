/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api;

import java.util.Set;

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
