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

package org.xipki.commons.security.p11.keystore;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.p11.P11ModuleConf;

/**
 * @author Lijun Liao
 */

public class KeystoreP11ModulePool {

    private static final Logger LOG = LoggerFactory.getLogger(KeystoreP11ModulePool.class);

    private final Map<String, KeystoreP11Module> modules = new HashMap<>();

    private String defaultModuleName;

    private static KeystoreP11ModulePool INSTANCE = new KeystoreP11ModulePool();

    public synchronized void removeModule(
            final String moduleName) {
        KeystoreP11Module module = modules.remove(moduleName);
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
                LOG.warn(LogUtil.buildExceptionLogFormat(message),
                        t.getClass().getName(), t.getMessage());
            }
            LOG.debug(message, t);
        }
    }

    public KeystoreP11Module getModule(
            final String moduleName)
    throws SignerException {
        KeystoreP11Module module = modules.get(moduleName);
        if (module == null && defaultModuleName != null
                && SecurityFactory.DEFAULT_P11MODULE_NAME.equals(moduleName)) {
            module = modules.get(defaultModuleName);
        }
        return module;
    }

    public synchronized KeystoreP11Module getModule(
            final P11ModuleConf moduleConf)
    throws SignerException {
        KeystoreP11Module extModule = modules.get(moduleConf.getName());
        if (extModule == null) {
            extModule = new KeystoreP11Module(moduleConf);
            modules.put(moduleConf.getName(), extModule);
        }

        return extModule;
    }

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

    public static KeystoreP11ModulePool getInstance() {
        return INSTANCE;
    }

}
