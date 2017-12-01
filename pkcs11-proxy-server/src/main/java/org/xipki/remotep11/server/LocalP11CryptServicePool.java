/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.remotep11.server;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.HashAlgoType;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.P11CryptService;
import org.xipki.security.pkcs11.P11CryptServiceFactory;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class LocalP11CryptServicePool {

    private static final Logger LOG = LoggerFactory.getLogger(LocalP11CryptServicePool.class);

    private P11CryptServiceFactory p11CryptServiceFactory;

    private Map<Short, P11CryptService> p11CryptServices = new HashMap<>();

    private AtomicBoolean initialized = new AtomicBoolean(false);

    public LocalP11CryptServicePool() {
    }

    public void setP11CryptServiceFactory(final P11CryptServiceFactory p11CryptServiceFactory) {
        this.p11CryptServiceFactory = p11CryptServiceFactory;
    }

    public boolean isInitialized() {
        return initialized.get();
    }

    public void init() throws P11TokenException, XiSecurityException {
        LOG.info("initializing ...");
        if (initialized.get()) {
            LOG.info("already initialized, skipping ...");
            return;
        }

        if (p11CryptServiceFactory == null) {
            throw new IllegalStateException("securityFactory is not configured");
        }

        Set<String> moduleNames = p11CryptServiceFactory.moduleNames();
        for (String moduleName : moduleNames) {
            P11CryptService p11Service = p11CryptServiceFactory.getP11CryptService(moduleName);
            if (p11Service != null) {
                short moduleId = deriveModuleId(moduleName);
                String hexModuleId = "0x" + Integer.toHexString(moduleId);
                if (p11CryptServices.containsKey(moduleId)) {
                    throw new P11TokenException(
                            "module Id " + moduleId + " for name " + moduleName
                            + " already used, use another module name");
                }
                p11CryptServices.put(moduleId, p11Service);
                LOG.info("map module name '{}' to ID {}({}), access path: "
                        + "'proxy:url=https://<host>:<port>/p11proxy,module={}'",
                        moduleName, moduleId, hexModuleId, hexModuleId);
            }
        }

        initialized.set(true);
        LOG.info("initialized");
    }

    public P11CryptService getP11CryptService(final short moduleId) {
        return p11CryptServices.get(moduleId);
    }

    /* ID = SHA1(moduleName.getBytes("UTF-8")[1..15] */
    private static short deriveModuleId(String moduleName) throws XiSecurityException {
        byte[] hash;
        try {
            hash = HashAlgoType.SHA1.hash(moduleName.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException ex) {
            throw new XiSecurityException("Unsupported charset UTF-8");
        }
        int intCode = 0x7FFF & ((0xFF & hash[0]) << 8) | (0xFF & hash[1]);
        return (short) intCode;
    }

}
