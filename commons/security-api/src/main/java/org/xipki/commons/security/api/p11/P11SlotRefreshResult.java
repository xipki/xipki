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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.annotation.Nonnull;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.X509Cert;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11SlotRefreshResult {

    private final Map<P11ObjectIdentifier, P11Identity> entities = new HashMap<>();

    private final Map<P11ObjectIdentifier, X509Cert> certificates = new HashMap<>();

    private final Set<Long> mechanisms = new HashSet<>();

    public P11SlotRefreshResult() {
    }

    public Map<P11ObjectIdentifier, P11Identity> getEntities() {
        return entities;
    }

    public Map<P11ObjectIdentifier, X509Cert> getCertificates() {
        return certificates;
    }

    public Set<Long> getMechanisms() {
        return mechanisms;
    }

    public void addEntity(
            final P11Identity entity) {
        ParamUtil.requireNonNull("entity", entity);
        this.entities.put(entity.getEntityId().getObjectId(), entity);
    }

    public void addMechanism(
            final long mechanism) {
        this.mechanisms.add(mechanism);
    }

    public void addCertificate(
            final P11ObjectIdentifier objectId,
            final X509Cert certificate) {
        ParamUtil.requireNonNull("objectId", objectId);
        ParamUtil.requireNonNull("certificate", certificate);
        this.certificates.put(objectId, certificate);
    }

    public X509Cert getCertForId(
            @Nonnull final byte[] id) {
        for (P11ObjectIdentifier objId : certificates.keySet()) {
            if (objId.matchesId(id)) {
                return certificates.get(objId);
            }
        }
        return null;
    }
}
