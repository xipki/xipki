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

package org.xipki.commons.security.api.p11;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nonnull;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.p11.P11Conf;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11CryptServiceFactory;
import org.xipki.commons.security.api.p11.P11Module;
import org.xipki.commons.security.api.p11.P11ModuleConf;
import org.xipki.commons.security.api.p11.P11TokenException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class AbstractP11CryptServiceFactory implements P11CryptServiceFactory {

    private static final Map<String, P11CryptService> SERVICES = new HashMap<>();

    private P11Conf p11Conf;

    @Override
    public void init(
            final P11Conf p11Conf) {
        this.p11Conf = ParamUtil.requireNonNull("p11Conf", p11Conf);
    }

    @Override
    public P11CryptService getP11CryptService(
            final String moduleName)
    throws SecurityException, P11TokenException {
        if (p11Conf == null) {
            throw new IllegalStateException("please call init() first");
        }

        ParamUtil.requireNonBlank("moduleName", moduleName);
        P11ModuleConf conf = p11Conf.getModuleConf(moduleName);
        if (conf == null) {
            throw new SecurityException("PKCS#11 module " + moduleName + " is not defined");
        }

        synchronized (SERVICES) {
            P11CryptService instance = SERVICES.get(moduleName);
            if (instance == null) {
                instance = new P11CryptService(getModule(conf));
                SERVICES.put(moduleName, instance);
            }

            return instance;
        }
    }

    protected abstract P11Module getModule(
            @Nonnull P11ModuleConf moduleConf)
    throws P11TokenException;

}
