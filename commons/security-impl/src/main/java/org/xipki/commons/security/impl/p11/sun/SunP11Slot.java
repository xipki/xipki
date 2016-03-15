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

package org.xipki.commons.security.impl.p11.sun;

import java.security.Provider;
import java.security.Provider.Service;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.p11.P11Constants;
import org.xipki.commons.security.api.p11.P11MechanismFilter;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.p11.P11UnknownEntityException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class SunP11Slot {

    private static final Logger LOG = LoggerFactory.getLogger(SunP11Slot.class);

    private final String moduleName;

    private final P11SlotIdentifier slotId;

    private Set<Long> supportedMechanisms = new HashSet<>();

    SunP11Slot(
            final String moduleName,
            final P11SlotIdentifier slotId,
            final P11MechanismFilter mechanismFilter,
            final Provider provider) {
        this.moduleName = ParamUtil.requireNonBlank("moduleName", moduleName);
        this.slotId = ParamUtil.requireNonNull("slotId", slotId);

        Set<Service> services = provider.getServices();
        for (Service service : services) {
            String type = service.getType();
            String algo = service.getAlgorithm();

            if ("Cipher".equalsIgnoreCase(type)) {
                if ("RSA/ECB/NoPadding".equals(algo)) {
                    addMechanism(P11Constants.CKM_RSA_X_509, mechanismFilter);
                    addMechanism(P11Constants.CKM_RSA_PKCS, mechanismFilter);
                    addMechanism(P11Constants.CKM_SHA1_RSA_PKCS, mechanismFilter);
                    addMechanism(P11Constants.CKM_SHA224_RSA_PKCS, mechanismFilter);
                    addMechanism(P11Constants.CKM_SHA256_RSA_PKCS, mechanismFilter);
                    addMechanism(P11Constants.CKM_SHA384_RSA_PKCS, mechanismFilter);
                    addMechanism(P11Constants.CKM_SHA512_RSA_PKCS, mechanismFilter);
                }
                continue;
            } else if ("Signature".equalsIgnoreCase(type)) {
                if ("SHA1withRSA".equalsIgnoreCase(algo)) {
                    addMechanism(P11Constants.CKM_SHA1_RSA_PKCS, mechanismFilter);
                } else if ("SHA224withRSA".equalsIgnoreCase(algo)) {
                    addMechanism(P11Constants.CKM_SHA224_RSA_PKCS, mechanismFilter);
                } else if ("SHA256withRSA".equalsIgnoreCase(algo)) {
                    addMechanism(P11Constants.CKM_SHA256_RSA_PKCS, mechanismFilter);
                } else if ("SHA384withRSA".equalsIgnoreCase(algo)) {
                    addMechanism(P11Constants.CKM_SHA384_RSA_PKCS, mechanismFilter);
                } else if ("SHA512withRSA".equalsIgnoreCase(algo)) {
                    addMechanism(P11Constants.CKM_SHA512_RSA_PKCS, mechanismFilter);
                } else if ("SHA1withDSA".equalsIgnoreCase(algo)) {
                    addMechanism(P11Constants.CKM_DSA_SHA1, mechanismFilter);
                } else if ("NONEwithDSA".equalsIgnoreCase(algo)) {
                    addMechanism(P11Constants.CKM_DSA, mechanismFilter);
                } else if ("SHA1withECDSA".equalsIgnoreCase(algo)) {
                    addMechanism(P11Constants.CKM_ECDSA_SHA1, mechanismFilter);
                } else if ("NONEwithECDSA".equalsIgnoreCase(algo)) {
                    addMechanism(P11Constants.CKM_ECDSA, mechanismFilter);
                }
            }
        }

        this.supportedMechanisms = Collections.unmodifiableSet(supportedMechanisms);
        if (LOG.isInfoEnabled()) {
            LOG.info("module {}, slot {}: supported mechanisms: {}", moduleName, slotId,
                    this.supportedMechanisms);
        }
    }

    String getModuleName() {
        return moduleName;
    }

    private void addMechanism(
            final long mechanism,
            final P11MechanismFilter filter) {
        if (filter.isMechanismPermitted(slotId, mechanism)) {
            supportedMechanisms.add(mechanism);
        }
    }

    Set<Long> getSupportedMechanisms()
    throws P11TokenException {
        return supportedMechanisms;
    }

    boolean supportsMechanism(
            final long mechanism)
    throws P11UnknownEntityException {
        return supportedMechanisms.contains(mechanism);
    }

}
