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
import java.util.HashMap;
import java.util.Map;
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
import org.xipki.commons.security.api.p11.P11Module;
import org.xipki.commons.security.api.p11.P11ModuleConf;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.pkcs11.internal.emulator.EmulatorP11Module;
import org.xipki.commons.security.pkcs11.internal.iaik.IaikP11Module;
import org.xipki.commons.security.pkcs11.internal.proxy.ProxyP11Module;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11CryptServiceFactoryImpl implements P11CryptServiceFactory {

    private static final Logger LOG = LoggerFactory.getLogger(P11CryptServiceFactoryImpl.class);

    private static final Map<String, P11CryptService> services = new HashMap<>();

    private static final Map<String, P11Module> modules = new HashMap<>();

    private SecurityFactory securityFactory;

    private P11Conf p11Conf;

    private String pkcs11ConfFile;

    public synchronized void init()
    throws InvalidConfException, IOException {
        if (p11Conf != null) {
            return;
        }
        if (StringUtil.isBlank(pkcs11ConfFile)) {
            LOG.info("no pkcs11ConfFile is configured");
            return;
        }

        this.p11Conf = new P11Conf(new FileInputStream(pkcs11ConfFile), securityFactory);
    }

    public synchronized P11CryptService getP11CryptService(
            final String moduleName)
    throws SecurityException, P11TokenException {
        if (p11Conf == null) {
            throw new IllegalStateException("please set pkcs11ConfFile and then call init() first");
        }

        final String name = getModuleName(moduleName);
        P11ModuleConf conf = p11Conf.getModuleConf(name);
        if (conf == null) {
            throw new SecurityException("PKCS#11 module " + name + " is not defined");
        }

        P11CryptService instance = services.get(moduleName);
        if (instance != null) {
            return instance;
        }

        String nativeLib = conf.getNativeLibrary();
        P11Module p11Module = modules.get(nativeLib);
        if (p11Module == null) {
            if (StringUtil.startsWithIgnoreCase(nativeLib, "proxy:")) {
                p11Module = ProxyP11Module.getInstance(conf);
            } else if (StringUtil.startsWithIgnoreCase(nativeLib, "emulator:")) {
                p11Module = EmulatorP11Module.getInstance(conf);
            } else {
                p11Module = IaikP11Module.getInstance(conf);
            }
        }

        modules.put(nativeLib, p11Module);
        instance = new P11CryptService(p11Module);
        services.put(moduleName, instance);

        return instance;
    }

    private String getModuleName(
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

    public void setSecurityFactory(
            final SecurityFactory securityFactory) {
        this.securityFactory = securityFactory;
    }

    public void shutdown() {
        for (String pk11Lib : modules.keySet()) {
            try {
                modules.get(pk11Lib).close();
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not close PKCS11 Module " + pk11Lib);
            }
        }
        modules.clear();
        services.clear();
    }

    @Override
    public Set<String> getModuleNames() {
        if (p11Conf == null) {
            throw new IllegalStateException("pkcs11ConfFile is not set");
        }
        return p11Conf.getModuleNames();
    }

}
