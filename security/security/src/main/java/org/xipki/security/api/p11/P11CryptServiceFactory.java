/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api.p11;

import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public interface P11CryptServiceFactory
{
    void init(P11Control p11Control);

    P11CryptService createP11CryptService(String moduleName)
    throws SignerException;
}
