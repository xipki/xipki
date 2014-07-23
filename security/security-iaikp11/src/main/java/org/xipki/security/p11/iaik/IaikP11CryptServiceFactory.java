/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11.iaik;

import java.util.Set;

import org.xipki.security.api.P11CryptService;
import org.xipki.security.api.P11CryptServiceFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public class IaikP11CryptServiceFactory implements P11CryptServiceFactory
{

    @Override
    public P11CryptService createP11CryptService(String pkcs11Module,
            char[] password)
    throws SignerException
    {
        return createP11CryptService(pkcs11Module, password, null, null);
    }

    @Override
    public P11CryptService createP11CryptService(String pkcs11Module, char[] password,
            Set<Integer> includeSlotIndexes, Set<Integer> excludeSlotIndexes)
    throws SignerException
    {
        return IaikP11CryptService.getInstance(pkcs11Module, password, includeSlotIndexes, excludeSlotIndexes);
    }

}
