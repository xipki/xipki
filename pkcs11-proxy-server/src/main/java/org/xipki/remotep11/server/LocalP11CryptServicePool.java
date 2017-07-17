/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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
