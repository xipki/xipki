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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.security.p11.iaik;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.LogUtil;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11ModuleConf;

import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * @author Lijun Liao
 */

public class IaikP11ModulePool {

    private static final Logger LOG = LoggerFactory.getLogger(IaikP11ModulePool.class);

    private final Map<String, IaikP11Module> modules = new HashMap<>();

    private String defaultModuleName;

    private static IaikP11ModulePool INSTANCE = new IaikP11ModulePool();

    public synchronized void removeModule(
            final String moduleName) {
        IaikP11Module module = modules.remove(moduleName);
        if (module == null && defaultModuleName != null
                && SecurityFactory.DEFAULT_P11MODULE_NAME.equals(moduleName)) {
            module = modules.remove(defaultModuleName);
        }

        if (module == null) {
            return;
        }

        try {
            LOG.info("removed module {}", moduleName);
            module.close();
            LOG.info("finalized module {}", moduleName);
        } catch (Throwable t) {
            final String message = "could not finalize the module " + moduleName;
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(),
                        t.getMessage());
            }
            LOG.debug(message, t);
        }
    }

    public IaikP11Module getModule(
            final String moduleName)
    throws SignerException {
        IaikP11Module module = modules.get(moduleName);
        if (module == null && defaultModuleName != null
                && SecurityFactory.DEFAULT_P11MODULE_NAME.equals(moduleName)) {
            module = modules.get(defaultModuleName);
        }
        return module;
    }

    public synchronized IaikP11Module getModule(
            final P11ModuleConf moduleConf)
    throws SignerException {
        IaikP11Module extModule = modules.get(moduleConf.getName());
        if (extModule != null) {
            return extModule;
        }

        Module module;

        try {
            module = Module.getInstance(moduleConf.getNativeLibrary());
        } catch (IOException e) {
            final String msg = "could not load the PKCS#11 module " + moduleConf.getName();
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(msg), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(msg, e);
            throw new SignerException(msg);
        }

        try {
            module.initialize(new DefaultInitializeArgs());
        } catch (iaik.pkcs.pkcs11.wrapper.PKCS11Exception e) {
            if (e.getErrorCode() != PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
                final String message = "PKCS11Exception";
                if (LOG.isErrorEnabled()) {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                            e.getMessage());
                }
                LOG.debug(message, e);
                close(module);
                throw new SignerException(e.getMessage());
            } else {
                LOG.info("PKCS#11 module already initialized");
                if (LOG.isInfoEnabled()) {
                    try {
                        LOG.info("pkcs11.getInfo():\n{}", module.getInfo());
                    } catch (TokenException e2) {
                        LOG.debug("module.getInfo()", e2);
                    }
                }
            }
        } catch (Throwable t) {
            final String message = "unexpected Exception: ";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(),
                        t.getMessage());
            }
            LOG.debug(message, t);
            close(module);
            throw new SignerException(t.getMessage());
        }

        extModule = new IaikP11Module(module, moduleConf);
        modules.put(moduleConf.getName(), extModule);

        return extModule;
    } // nmethod getModule

    @Override
    protected void finalize()
    throws Throwable {
        super.finalize();
        shutdown();
    }

    public synchronized void shutdown() {
        for (String pk11Lib : modules.keySet()) {
            modules.get(pk11Lib).close();
        }
        modules.clear();
    }

    public String getDefaultModuleName() {
        return defaultModuleName;
    }

    public void setDefaultModuleName(
            final String defaultModuleName) {
        this.defaultModuleName = defaultModuleName;
    }

    public static IaikP11ModulePool getInstance() {
        return INSTANCE;
    }

    private static void close(
            final Module module) {
        if (module != null) {
            LOG.info("close", "close pkcs11 module: {}", module);
            try {
                module.finalize(null);
            } catch (Throwable t) {
                final String message = "error while module.finalize()";
                if (LOG.isErrorEnabled()) {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(),
                            t.getMessage());
                }
                LOG.debug(message, t);
            }
        }
    }

}
