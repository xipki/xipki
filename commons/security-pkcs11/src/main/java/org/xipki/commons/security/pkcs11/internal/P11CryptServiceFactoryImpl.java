/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.security.pkcs11.internal;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.InvalidConfException;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.exception.SecurityException;
import org.xipki.commons.security.api.p11.P11Conf;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11CryptServiceFactory;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.pkcs11.internal.iaik.IaikP11CryptServiceEngine;
import org.xipki.commons.security.pkcs11.internal.keystore.KeystoreP11CryptServiceEngine;
import org.xipki.commons.security.pkcs11.internal.proxy.ProxyP11CryptServiceEngine;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11CryptServiceFactoryImpl implements P11CryptServiceFactory {

    private static final Logger LOG = LoggerFactory.getLogger(P11CryptServiceFactoryImpl.class);

    private String pkcs11Engine;

    private P11Conf p11Conf;

    private P11CryptServiceEngine engine;

    private SecurityFactory securityFactory;

    private String pkcs11ConfFile;

    private boolean initialized;

    private synchronized void init()
    throws SecurityException {
        if (engine != null) {
            return;
        }

        if (initialized) {
            throw new SecurityException("initialization has been"
                    + " processed and failed, no retry");
        }

        try {
            initPkcs11ModuleConf();

            if ("IAIK-PKCS11".equalsIgnoreCase(pkcs11Engine)) {
                engine = new IaikP11CryptServiceEngine(p11Conf);
            } else if ("KEYSTORE-PKCS11".equalsIgnoreCase(pkcs11Engine)) {
                engine = new KeystoreP11CryptServiceEngine(p11Conf);
            } else if ("PROXY-PKCS11".equalsIgnoreCase(pkcs11Engine)) {
                engine = new ProxyP11CryptServiceEngine(p11Conf);
            } else {
                throw new SecurityException("unknown pkcs11Engine: '" + pkcs11Engine + "'");
            }
        } finally {
            initialized = true;
        }
    }

    private synchronized void initPkcs11ModuleConf() {
        if (p11Conf != null) {
            return;
        }

        if (StringUtil.isBlank(pkcs11ConfFile)) {
            throw new IllegalStateException("pkcs11ConfFile is not set");
        }

        try {
            this.p11Conf = new P11Conf(new FileInputStream(pkcs11ConfFile), securityFactory);
        } catch (InvalidConfException | IOException ex) {
            final String message = "invalid configuration file " + pkcs11ConfFile;
            LOG.error(LogUtil.getErrorLog(message), ex.getClass().getName(), ex.getMessage());
            LOG.debug(message, ex);

            throw new RuntimeException(message);
        }
    }

    public P11CryptService getP11CryptService(
            final String moduleName)
    throws SecurityException, P11TokenException {
        init();
        return engine.getP11CryptService(getPkcs11ModuleName(moduleName));
    }

    public Set<String> getP11ModuleNames() {
        initPkcs11ModuleConf();
        return (p11Conf == null)
                ? null
                : p11Conf.getModuleNames();
    }

    private String getPkcs11ModuleName(
            final String moduleName) {
        return (moduleName == null)
                ? DEFAULT_P11MODULE_NAME
                : moduleName;
    }

    public void setPkcs11ConfFile(
            final String confFile) {
        if (StringUtil.isBlank(confFile)) {
            this.pkcs11ConfFile = null;
        } else {
            this.pkcs11ConfFile = confFile;
        }
    }

    public void setPkcs11Engine(
            final String pkcs11Engine) {
        this.pkcs11Engine = pkcs11Engine;
    }

    public void setSecurityFactory(
            final SecurityFactory securityFactory) {
        this.securityFactory = securityFactory;
    }

    public void shutdown() {
        if (engine == null) {
            return;
        }

        try {
            engine.shutdown();
        } catch (Throwable th) {
            LOG.error("could not shutdown: " + th.getMessage(), th);
        }
    }

    @Override
    public Set<String> getModuleNames() {
        initPkcs11ModuleConf();
        return p11Conf.getModuleNames();
    }

}
