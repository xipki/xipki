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

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.xipki.commons.pkcs11proxy.common.P11ProxyConstants;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.P11Module;
import org.xipki.commons.security.api.p11.P11ModuleConf;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.p11.parameters.P11Params;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ProxyP11CryptService implements P11CryptService {

    private ProxyP11Module module;

    public ProxyP11CryptService(
            final P11ModuleConf moduleConf)
    throws P11TokenException {
        this.module = new ProxyP11Module(moduleConf);
    }

    public int getServerVersion()
    throws P11TokenException {
        ASN1Encodable result = module.send(P11ProxyConstants.ACTION_getVersion,
                DERNull.INSTANCE);

        ASN1Integer derInt;
        try {
            derInt = ASN1Integer.getInstance(result);
        } catch (IllegalArgumentException ex) {
            throw new P11TokenException("the returned result is not INTEGER");
        }

        return (derInt == null)
                ? 0
                : derInt.getPositiveValue().intValue();
    }

    @Override
    public void refresh()
    throws P11TokenException {
        // FIXME
    }

    @Override
    public Set<Long> getMechanisms(
            final P11SlotIdentifier slotId)
    throws P11TokenException {
        return module.getSlot(slotId).getMechanisms();
    }

    @Override
    public boolean supportsMechanism(
            final P11SlotIdentifier slotId,
            final long mechanism)
    throws P11TokenException {
        return module.getSlot(slotId).supportsMechanism(mechanism);
    }

    @Override
    public P11Module getModule()
    throws P11TokenException {
        return module;
    }

    @Override
    public byte[] sign(
            final P11EntityIdentifier entityId,
            final long mechanism,
            final P11Params parameters,
            final byte[] content)
    throws P11TokenException, SecurityException {
        P11Identity identity =
                module.getSlot(entityId.getSlotId()).getIdentity(entityId.getKeyId());
        return identity.sign(mechanism, parameters, content);
    }

    @Override
    public PublicKey getPublicKey(
            final P11EntityIdentifier entityId)
    throws P11TokenException {
        P11Identity identity =
                module.getSlot(entityId.getSlotId()).getIdentity(entityId.getKeyId());
        return identity.getPublicKey();
    }

    @Override
    public X509Certificate getCertificate(
            final P11EntityIdentifier entityId)
    throws P11TokenException {
        X509Certificate[] certs = getCertificates(entityId);
        return (certs == null || certs.length < 1)
                ? null
                : certs[0];
    }

    @Override
    public X509Certificate[] getCertificates(
            final P11EntityIdentifier entityId)
    throws P11TokenException {
        P11Identity identity =
                module.getSlot(entityId.getSlotId()).getIdentity(entityId.getKeyId());
        return identity.getCertificateChain();
    }

}
