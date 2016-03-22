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

package org.xipki.commons.security.impl.p11.proxy;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.p11.P11ModuleConf;
import org.xipki.commons.security.api.p11.P11TokenException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class RemoteP11ModulePool {

    private static final Logger LOG = LoggerFactory.getLogger(RemoteP11ModulePool.class);

    private static final RemoteP11ModulePool INSTANCE = new RemoteP11ModulePool();

    private final Map<String, RemoteP11Module> modules = new HashMap<>();

    synchronized void removeModule(
            final String moduleName) {
        ParamUtil.requireNonNull("moduleName", moduleName);
        RemoteP11Module module = modules.remove(moduleName);
        if (module == null) {
            return;
        }

        try {
            LOG.info("removed module {}", moduleName);
            module.close();
            LOG.info("finalized module {}", moduleName);
        } catch (Throwable th) {
            final String message = "could not finalize the module " + moduleName;
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), th.getClass().getName(),
                        th.getMessage());
            }
            LOG.debug(message, th);
        }
    }

    public RemoteP11Module getModule(
            final String moduleName) {
        ParamUtil.requireNonNull("moduleName", moduleName);
        return modules.get(moduleName);
    }

    public synchronized RemoteP11Module getModule(
            final P11ModuleConf moduleConf)
    throws P11TokenException {
        ParamUtil.requireNonNull("moduleConf", moduleConf);
        RemoteP11Module module = modules.get(moduleConf.getName());
        if (module == null) {
            P11Communicator communicator = new P11Communicator(moduleConf.getNativeLibrary());
            module = new RemoteP11Module(moduleConf, communicator);
            modules.put(moduleConf.getName(), module);
        }

        return module;
    } // nmethod getModule

    public synchronized void shutdown() {
        for (String pk11Lib : modules.keySet()) {
            try {
                modules.get(pk11Lib).close();
            } catch (Throwable th) {
                LOG.error("could not close PKCS11 Module " + pk11Lib + ":" + th.getMessage(),
                        th);
            }
        }
        modules.clear();
    }

    public static RemoteP11ModulePool getInstance() {
        return INSTANCE;
    }

}
