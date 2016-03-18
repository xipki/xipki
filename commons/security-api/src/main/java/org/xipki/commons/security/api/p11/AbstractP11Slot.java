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

package org.xipki.commons.security.api.p11;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.annotation.Nonnull;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class AbstractP11Slot implements P11Slot {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractP11Slot.class);

    protected final String moduleName;

    protected final P11SlotIdentifier slotId;

    private final CopyOnWriteArrayList<P11KeyIdentifier> keyIdentifiers =
            new CopyOnWriteArrayList<>();

    private final ConcurrentHashMap<P11KeyIdentifier, P11Identity> identities =
            new ConcurrentHashMap<>();

    private final Set<Long> mechanisms = Collections.emptySet();

    protected AbstractP11Slot(
            final String moduleName,
            final P11SlotIdentifier slotId,
            final P11MechanismFilter mechanismFilter)
    throws P11TokenException {
        ParamUtil.requireNonNull("mechanismFilter", mechanismFilter);
        this.moduleName = ParamUtil.requireNonBlank("moduleName", moduleName);
        this.slotId = ParamUtil.requireNonNull("slotId", slotId);
    }

    protected static String getDescription(
            final byte[] keyId,
            final char[] keyLabel) {
        StringBuilder sb = new StringBuilder();
        sb.append("id ");
        if (keyId == null) {
            sb.append("null");
        } else {
            sb.append(Hex.toHexString(keyId));
        }

        sb.append(" and label ");
        if (keyLabel == null) {
            sb.append("null");
        } else {
            sb.append(new String(keyLabel));
        }
        return sb.toString();
    }

    protected static String hex(
            @Nonnull final byte[] bytes) {
        return Hex.toHexString(bytes).toUpperCase();
    }

    protected void addCaCertificate(
            @Nonnull final X509Certificate caCert) {
        // FIXME: implement me
    }

    protected void removeCaCertificate(
            @Nonnull final X509Certificate caCert) {
        // FIXME: implement me
    }

    protected void clearMechanisms() {
        mechanisms.clear();
        LOG.info("module {}, slot {}: cleared mechanisms", moduleName, slotId);
    }

    protected boolean removeMechanism(
            final long mechanism) {
        boolean removed = mechanisms.remove(mechanism);
        LOG.info("module {}, slot {}: removed mechanism: {}", moduleName, slotId,
                mechanism);
        return removed;
    }

    protected void addMechanism(
            final long mechanism) {
        this.mechanisms.add(mechanism);
        LOG.info("module {}, slot {}: added mechanism: {}", moduleName, slotId,
                mechanism);
    }

    protected void setIdentities(
            @Nonnull final Set<? extends P11Identity> identities)
    throws P11DuplicateEntityException {
        for (P11Identity identity : identities) {
            addIdentity(identity);
        }

        if (LOG.isInfoEnabled()) {
            StringBuilder sb = new StringBuilder();
            sb.append("slot ").append(slotId);
            sb.append(": initialized ").append(this.identities.size()).append(" PKCS#11 Keys:\n");
            for (P11KeyIdentifier keyId : keyIdentifiers) {
                P11Identity identity = this.identities.get(keyId);
                sb.append("\t(").append(keyId);
                sb.append(", algo=").append(identity.getPublicKey().getAlgorithm()).append(")\n");
            }

            LOG.info(sb.toString());
        }
    }

    protected void addIdentity(
            final P11Identity identity)
    throws P11DuplicateEntityException {
        if (!slotId.equals(identity.getEntityId().getSlotId())) {
            throw new IllegalArgumentException("invalid identity");
        }

        P11KeyIdentifier keyId = identity.getEntityId().getKeyId();
        if (hasIdentity(keyId)) {
            throw new P11DuplicateEntityException(slotId, keyId);
        }

        List<P11KeyIdentifier> ids = new ArrayList<>(keyIdentifiers);
        ids.add(keyId);
        Collections.sort(ids);
        keyIdentifiers.clear();
        keyIdentifiers.add(keyId);
        identities.put(keyId, identity);
    }

    protected void deleteIdentity(
            final P11KeyIdentifier keyId)
    throws P11DuplicateEntityException {
        if (hasIdentity(keyId)) {
            LOG.warn("could not find key " + keyId);
            return;
        }
        keyIdentifiers.remove(keyId);
        identities.remove(keyId);
        LOG.info("deleted key " + keyId);
    }

    @Override
    public boolean hasIdentity(
            final P11KeyIdentifier keyId) {
        return keyIdentifiers.contains(keyId);
    }

    @Override
    public Set<Long> getMechanisms() {
        return Collections.unmodifiableSet(mechanisms);
    }

    @Override
    public boolean supportsMechanism(
            final long mechanism) {
        return mechanisms.contains(mechanism);
    }

    @Override
    public void assertMechanismSupported(
            final long mechanism)
    throws P11UnsupportedMechanismException {
        if (!mechanisms.contains(mechanism)) {
            throw new P11UnsupportedMechanismException(mechanism, slotId);
        }
    }

    @Override
    public List<P11KeyIdentifier> getKeyIdentifiers()
    throws P11TokenException {
        return Collections.unmodifiableList(keyIdentifiers);
    }

    @Override
    public String getModuleName() {
        return moduleName;
    }

    @Override
    public P11SlotIdentifier getSlotId() {
        return slotId;
    }

    @Override
    public P11Identity getIdentity(
            final P11KeyIdentifier keyId)
    throws P11UnknownEntityException {
        P11Identity ident = identities.get(keyId);
        if (ident == null) {
            throw new P11UnknownEntityException(slotId, keyId);
        }
        return ident;
    }

    @Override
    public P11KeyIdentifier getKeyIdForId(
            final byte[] keyId)
    throws P11UnknownEntityException {
        for (P11KeyIdentifier id : keyIdentifiers) {
            if (Arrays.equals(keyId, id.getKeyId())) {
                return id;
            }
        }
        throw new P11UnknownEntityException("unknown PKCS#11 key with id "
                + Hex.toHexString(keyId));
    }

    @Override
    public P11KeyIdentifier getKeyIdForLabel(
            final String keyLabel)
    throws P11UnknownEntityException {
        for (P11KeyIdentifier id : keyIdentifiers) {
            if (id.getKeyLabel().equals(keyLabel)) {
                return id;
            }
        }
        throw new P11UnknownEntityException("unknown PKCS#11 key with label " + keyLabel);
    }

}
