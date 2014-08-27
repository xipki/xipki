/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api.p11;

import java.util.Collection;

import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public interface P11CryptServiceFactory
{
    void init(String defaultModuleName, Collection<P11ModuleConf> moduleConfs);

    P11CryptService createP11CryptService(String moduleName)
    throws SignerException;
}
