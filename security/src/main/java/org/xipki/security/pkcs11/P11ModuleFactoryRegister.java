// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.xipki.pkcs11.wrapper.TokenException;

import java.io.Closeable;

/**
 * Register of {@link P11ModuleFactory}s.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public interface P11ModuleFactoryRegister extends Closeable {

  P11Module getP11Module(P11ModuleConf conf) throws TokenException;

}
