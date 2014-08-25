/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11.sun;

import java.util.Set;

import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11CryptServiceFactory;

/**
 * @author Lijun Liao
 */

public class SunP11CryptServiceFactory implements P11CryptServiceFactory
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
         return SunP11CryptService.getInstance(pkcs11Module, password, includeSlotIndexes, excludeSlotIndexes);
    }

}
