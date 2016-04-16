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

package org.xipki.commons.remotep11.server.impl;

import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.exception.SecurityException;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11CryptServiceFactory;
import org.xipki.commons.security.api.p11.P11TokenException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class LocalP11CryptServicePool {

    private static final Logger LOG = LoggerFactory.getLogger(LocalP11CryptServicePool.class);

    private P11CryptServiceFactory p11CryptServiceFactory;

    private Map<String, P11CryptService> p11CryptServices = new HashMap<>();

    private AtomicBoolean initialized = new AtomicBoolean(false);

    public LocalP11CryptServicePool() {
    }

    public void setP11CryptServiceFactory(
            final P11CryptServiceFactory p11CryptServiceFactory) {
        this.p11CryptServiceFactory = p11CryptServiceFactory;
    }

    public boolean isInitialized() {
        return initialized.get();
    }

    public void asynInit() {
        Runnable initRun = new Runnable() {
            @Override
            public void run() {
                try {
                    init();
                } catch (Throwable th) {
                    LogUtil.error(LOG, th, "could not asynInit");
                }
            }
        };
        new Thread(initRun).start();
    }

    public void init()
    throws P11TokenException, SecurityException {
        LOG.info("initializing ...");
        if (initialized.get()) {
            LOG.info("already initialized, skipping ...");
            return;
        }

        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        if (p11CryptServiceFactory == null) {
            throw new IllegalStateException("securityFactory is not configured");
        }

        Set<String> moduleNames = p11CryptServiceFactory.getModuleNames();
        for (String moduleName : moduleNames) {
            P11CryptService p11Service = p11CryptServiceFactory.getP11CryptService(moduleName);
            if (p11Service != null) {
                p11CryptServices.put(moduleName, p11Service);
            }
        }

        initialized.set(true);
        LOG.info("initialized");
    }

    public P11CryptService getP11CryptService(
            final String moduleName) {
        ParamUtil.requireNonBlank("moduleName", moduleName);
        return p11CryptServices.get(moduleName);
    }

}
