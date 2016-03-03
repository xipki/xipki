/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.commons.security.impl.p11.remote;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.p11.P11Control;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11CryptServiceFactory;
import org.xipki.commons.security.api.p11.P11ModuleConf;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RemoteP11CryptServiceFactory implements P11CryptServiceFactory {

    private static final Logger LOG = LoggerFactory.getLogger(RemoteP11CryptServiceFactory.class);

    private P11Control p11Control;

    private final Map<String, RemoteP11CryptService> services = new HashMap<>();

    @Override
    public void init(
            final P11Control pP11Control) {
        this.p11Control = ParamUtil.requireNonNull("pP11Control", pP11Control);
    }

    @Override
    public P11CryptService createP11CryptService(
            final String moduleName)
    throws SignerException {
        ParamUtil.requireNonBlank("moduleName", moduleName);
        if (p11Control == null) {
            throw new IllegalStateException("please call init() first");
        }

        String localModuleName = moduleName;

        if (SecurityFactory.DEFAULT_P11MODULE_NAME.equals(localModuleName)) {
            localModuleName = p11Control.getDefaultModuleName();
        }

        P11ModuleConf moduleConf = p11Control.getModuleConf(localModuleName);
        if (moduleConf == null) {
            throw new SignerException("PKCS#11 module " + localModuleName + " is not defined");
        }

        synchronized (services) {
            RemoteP11CryptService service = services.get(localModuleName);
            if (service == null) {
                try {
                    service = new DefaultRemoteP11CryptService(moduleConf);
                    String url = ((DefaultRemoteP11CryptService) service).getServerUrl();
                    logServiceInfo(url, service);
                    services.put(moduleConf.getName(), service);
                } catch (Exception ex) {
                    LOG.error("could not createP11CryptService: {}", ex.getMessage());
                    LOG.debug("could not createP11CryptService", ex);
                    throw new SignerException(ex.getMessage(), ex);
                }
            }

            return service;
        }
    }

    private static void logServiceInfo(
            final String url,
            final RemoteP11CryptService service) {
        StringBuilder sb = new StringBuilder();
        sb.append("initialized RemoteP11CryptService (url=").append(url).append(")\n");

        P11SlotIdentifier[] slotIds;
        try {
            slotIds = service.getSlotIdentifiers();
        } catch (SignerException ex) {
            LOG.warn("RemoteP11CryptService.getSlotIdentifiers(); SignerException: "
                    + "url={}, message={}",
                    url, ex.getMessage());
            LOG.debug("RemoteP11CryptService.getSlotIdentifiers(); SignerException", ex);
            return;
        }

        if (slotIds == null || slotIds.length == 0) {
            sb.append("\tno slot is available");
            LOG.warn("{}", sb);
            return;
        }

        for (P11SlotIdentifier slotId : slotIds) {
            String[] keyLabels;
            try {
                keyLabels = service.getKeyLabels(slotId);
            } catch (SignerException ex) {
                LOG.warn("RemoteP11CryptService.getKeyLabels(); SignerException: "
                        + "url={}, slot={}, message={}",
                        new Object[]{url, slotId, ex.getMessage()});
                LOG.debug("RemoteP11CryptService.getKeyLabels(); SignerException", ex);
                continue;
            }

            if (keyLabels != null && keyLabels.length > 0) {
                for (String keyLabel : keyLabels) {
                    sb.append("\t(slot ").append(slotId);
                    sb.append(", label=").append(keyLabel).append(")\n");
                }
            }
        }

        LOG.info("{}", sb);
    }

}
